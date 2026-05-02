"""Tests for the ingestion pipeline (extract_to_parquet.py).

Uses moto to mock S3 — no real AWS calls needed.
"""

import json
import os
import sys
import pytest
import boto3
import pyarrow.parquet as pq
from io import BytesIO
from moto import mock_aws
from unittest.mock import patch

# Ensure the ingestion module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ingestion.extract_to_parquet import (
    classify_event,
    normalize_record,
    ParquetWriter,
    SCHEMAS,
)


# ── classify_event ──────────────────────────────────────────────


class TestClassifyEvent:
    def test_vpn_by_endpoint(self):
        record = {"vpn_endpoint": "vpn-west-1", "timestamp": "2025-10-01T00:00:00Z"}
        assert classify_event(record) == "vpn_logs"

    def test_vpn_by_event_id_prefix(self):
        record = {
            "event_type": "connect",
            "event_id": "vpn-abc123",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "vpn_logs"

    def test_ehr_by_patient_id(self):
        record = {
            "patient_id": "MRN-00001234",
            "employee_id": "EMP-001",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "ehr_access"

    def test_ehr_by_event_id_prefix(self):
        record = {"event_id": "ehr-xyz", "timestamp": "2025-10-01T00:00:00Z"}
        assert classify_event(record) == "ehr_access"

    def test_auth_by_method(self):
        record = {
            "auth_method": "password",
            "employee_id": "EMP-001",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "auth_logs"

    def test_http_by_method(self):
        record = {
            "http_method": "GET",
            "path": "/api/v1/patients",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "http_logs"

    def test_db_by_query_type(self):
        record = {
            "query_type": "SELECT",
            "table_name": "patients",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "db_queries"

    def test_cloudtrail_by_event_source(self):
        record = {
            "event_source": "s3.amazonaws.com",
            "event_name": "PutObject",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "cloudtrail"

    def test_network_by_destination_ip(self):
        record = {
            "destination_ip": "10.0.0.5",
            "source_ip": "10.0.0.1",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "network_flows"

    def test_unknown_event(self):
        record = {"foo": "bar", "timestamp": "2025-10-01T00:00:00Z"}
        assert classify_event(record) == "unknown"

    def test_priority_vpn_over_cloudtrail(self):
        """VPN should win even if event_source is also present."""
        record = {
            "vpn_endpoint": "vpn-west-1",
            "event_source": "vpn.amazonaws.com",
            "timestamp": "2025-10-01T00:00:00Z",
        }
        assert classify_event(record) == "vpn_logs"


# ── normalize_record ────────────────────────────────────────────


class TestNormalizeRecord:
    def test_serializes_nested_objects(self):
        record = {
            "timestamp": "2025-10-01T00:00:00Z",
            "event_id": "auth-001",
            "employee_id": "EMP-001",
            "event_type": "login_success",
            "auth_method": "password",
            "mfa_type": None,
            "source_ip": "10.0.0.1",
            "user_agent": "Mozilla/5.0",
            "geo": {"city": "San Francisco", "state": "CA", "country": "US"},
            "session_id": "sess-001",
            "risk_score": 0.1,
            "success": True,
        }
        normalized = normalize_record(record, "auth_logs")

        assert isinstance(normalized["geo"], str)
        assert json.loads(normalized["geo"]) == {
            "city": "San Francisco",
            "state": "CA",
            "country": "US",
        }

    def test_fills_missing_fields_with_none(self):
        record = {"timestamp": "2025-10-01T00:00:00Z"}
        normalized = normalize_record(record, "auth_logs")

        # All schema fields should be present
        schema_fields = {f.name for f in SCHEMAS["auth_logs"]}
        assert set(normalized.keys()) == schema_fields

        # Missing fields are None
        assert normalized["employee_id"] is None
        assert normalized["risk_score"] is None

    def test_drops_extra_fields(self):
        record = {
            "timestamp": "2025-10-01T00:00:00Z",
            "event_id": "auth-001",
            "extra_field": "should be dropped",
        }
        normalized = normalize_record(record, "auth_logs")
        assert "extra_field" not in normalized

    def test_unknown_type_returns_as_is(self):
        record = {"foo": "bar"}
        assert normalize_record(record, "unknown") == record


# ── ParquetWriter ───────────────────────────────────────────────


class TestParquetWriter:
    @mock_aws
    def test_flush_writes_parquet_to_s3(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "siem-data-test"
        s3.create_bucket(Bucket=bucket)

        writer = ParquetWriter(bucket)

        rows = [
            normalize_record(
                {
                    "timestamp": "2025-10-01T00:00:00Z",
                    "event_id": f"auth-{i:03d}",
                    "employee_id": "EMP-001",
                    "event_type": "login_success",
                    "auth_method": "password",
                    "mfa_type": None,
                    "source_ip": "10.0.0.1",
                    "user_agent": "Mozilla/5.0",
                    "geo": json.dumps({"city": "SF"}),
                    "session_id": "sess-001",
                    "risk_score": 0.1,
                    "success": True,
                },
                "auth_logs",
            )
            for i in range(5)
        ]

        for row in rows:
            writer.add(row, "auth_logs")

        writer.flush_all()

        # Verify object was created
        response = s3.list_objects_v2(
            Bucket=bucket, Prefix="processed/auth_logs/dt=2025-10-01/"
        )
        assert "Contents" in response
        assert len(response["Contents"]) == 1

        key = response["Contents"][0]["Key"]
        assert key == "processed/auth_logs/dt=2025-10-01/chunk_00000.parquet"

        # Verify Parquet contents
        obj = s3.get_object(Bucket=bucket, Key=key)
        table = pq.read_table(BytesIO(obj["Body"].read()))
        assert table.num_rows == 5
        assert "employee_id" in table.column_names

    @mock_aws
    def test_date_partitioning(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "siem-data-test"
        s3.create_bucket(Bucket=bucket)

        writer = ParquetWriter(bucket)

        # Add rows with different dates
        for date in ["2025-10-01", "2025-10-02"]:
            row = normalize_record(
                {
                    "timestamp": f"{date}T12:00:00Z",
                    "event_id": f"auth-{date}",
                    "employee_id": "EMP-001",
                    "event_type": "login_success",
                    "auth_method": "password",
                    "source_ip": "10.0.0.1",
                    "success": True,
                },
                "auth_logs",
            )
            writer.add(row, "auth_logs")

        writer.flush_all()

        response = s3.list_objects_v2(Bucket=bucket, Prefix="processed/auth_logs/")
        keys = [obj["Key"] for obj in response["Contents"]]

        assert any("dt=2025-10-01" in k for k in keys)
        assert any("dt=2025-10-02" in k for k in keys)

    def test_stats_tracking(self):
        writer = ParquetWriter("fake-bucket")
        # Just add to buffers, don't flush (would need real S3)
        writer.buffers["auth_logs"]["2025-10-01"].append({"data": 1})
        writer.stats["auth_logs"] += 1
        writer.buffers["http_logs"]["2025-10-01"].append({"data": 2})
        writer.stats["http_logs"] += 1

        assert writer.stats["auth_logs"] == 1
        assert writer.stats["http_logs"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
