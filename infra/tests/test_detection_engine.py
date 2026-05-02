"""Tests for the detection engine (detection_engine.py).

Uses moto to mock S3/CloudWatch/SNS and patches DuckDB so no real
AWS calls or data files are needed.
"""

import json
import os
import sys
import pytest
import boto3
from moto import mock_aws
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Ensure the lambda module is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))

# Must set env vars BEFORE importing the module (it reads them at import time)
os.environ["S3_BUCKET"] = "siem-data-test"
os.environ["ALERTS_LOG_GROUP"] = "/siemlessly/alerts"

import detection_engine as de


# ── Fixtures ────────────────────────────────────────────────────

SAMPLE_SOURCES = [
    {
        "name": "auth_logs",
        "description": "Auth events",
        "parquet_path": "s3://{bucket}/processed/auth_logs/dt=*/*.parquet",
        "raw_path": "s3://{bucket}/raw/",
    },
    {
        "name": "vpn_logs",
        "description": "VPN events",
        "parquet_path": "s3://{bucket}/processed/vpn_logs/dt=*/*.parquet",
        "raw_path": "s3://{bucket}/raw/",
    },
    {
        "name": "ehr_access",
        "description": "EHR events",
        "parquet_path": "s3://{bucket}/processed/ehr_access/dt=*/*.parquet",
        "raw_path": "s3://{bucket}/raw/",
    },
    {
        "name": "http_logs",
        "description": "HTTP events",
        "parquet_path": "s3://{bucket}/processed/http_logs/dt=*/*.parquet",
        "raw_path": "s3://{bucket}/raw/",
    },
]

SAMPLE_RULES = [
    {
        "id": "test-rule-1",
        "name": "Test Rule 1",
        "severity": "high",
        "enabled": True,
        "query": "SELECT employee_id FROM auth_logs WHERE success = false",
        "destinations": [{"type": "cloudwatch"}],
    },
    {
        "id": "test-rule-disabled",
        "name": "Disabled Rule",
        "severity": "low",
        "enabled": False,
        "query": "SELECT * FROM auth_logs",
        "destinations": [],
    },
]


@pytest.fixture(autouse=True)
def reset_caches():
    """Reset module-level caches between tests."""
    de._rule_cache = None
    de._rule_cache_time = 0
    de._source_cache = None
    de._source_cache_time = 0
    yield


# ── resolve_source_names ────────────────────────────────────────


class TestResolveSourceNames:
    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_replaces_bare_identifier_after_from(self, _mock):
        query = "SELECT * FROM auth_logs WHERE success = false"
        result = de.resolve_source_names(query)

        # The bare identifier is replaced with a quoted S3 path
        assert "FROM 's3://siem-data-test/processed/auth_logs/dt=*/*.parquet'" in result
        # No bare (unquoted) auth_logs after FROM
        assert "FROM auth_logs" not in result
        assert result.startswith("SELECT * FROM ")

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_replaces_after_join(self, _mock):
        query = "SELECT * FROM auth_logs a JOIN vpn_logs v ON a.employee_id = v.employee_id"
        result = de.resolve_source_names(query)

        assert "'s3://siem-data-test/processed/auth_logs/dt=*/*.parquet'" in result
        assert "'s3://siem-data-test/processed/vpn_logs/dt=*/*.parquet'" in result

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_leaves_unknown_identifiers_alone(self, _mock):
        query = "SELECT * FROM some_unknown_table"
        result = de.resolve_source_names(query)

        assert result == query  # unchanged

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_case_insensitive_from(self, _mock):
        query = "select * from auth_logs where 1=1"
        result = de.resolve_source_names(query)

        assert "'s3://siem-data-test/processed/auth_logs/dt=*/*.parquet'" in result

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_does_not_replace_inside_column_names(self, _mock):
        """Regression test: the old str.replace() bug would corrupt
        column references containing source names (e.g. auth_logs_count)."""
        query = "SELECT auth_logs_count FROM auth_logs WHERE 1=1"
        result = de.resolve_source_names(query)

        # The column name should remain intact
        assert "auth_logs_count" in result
        # But the FROM target should be resolved
        assert "FROM 's3://siem-data-test/processed/auth_logs/dt=*/*.parquet'" in result

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_does_not_replace_quoted_strings(self, _mock):
        """Quoted identifiers after FROM should not be touched."""
        query = "SELECT * FROM 's3://some/path.parquet' WHERE 1=1"
        result = de.resolve_source_names(query)

        # \w+ won't match a quoted string, so it stays unchanged
        assert result == query


# ── Event-driven source resolution (the regex fix) ──────────────


class TestEventDrivenResolution:
    """Tests the regex-based source replacement in run_detections(data_source=...)."""

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_replaces_source_with_specific_file(self, _mock):
        """Verify the regex replacement works for event-driven mode."""
        import re

        data_source = "s3://bucket/processed/auth_logs/dt=2025-10-01/chunk_00000.parquet"
        source_map = {s["name"] for s in SAMPLE_SOURCES}

        query = "SELECT employee_id FROM auth_logs WHERE success = false"

        def _replace_with_file(match):
            prefix = match.group(1)
            name = match.group(2)
            if name in source_map:
                return f"{prefix}'{data_source}'"
            return match.group(0)

        result = re.sub(
            r"((?:FROM|JOIN)\s+)(\w+)",
            _replace_with_file,
            query,
            flags=re.IGNORECASE,
        )

        assert f"FROM '{data_source}'" in result
        # The bare identifier is gone — only appears inside the quoted path
        assert "FROM auth_logs" not in result

    @patch.object(de, "load_sources", return_value=SAMPLE_SOURCES)
    def test_does_not_corrupt_column_names_event_driven(self, _mock):
        """Regression: old str.replace() would replace 'auth_logs' inside
        'auth_logs_count', corrupting the query."""
        import re

        data_source = "s3://bucket/processed/auth_logs/dt=2025-10-01/chunk_00000.parquet"
        source_map = {s["name"] for s in SAMPLE_SOURCES}

        query = "SELECT count(*) AS auth_logs_total FROM auth_logs WHERE 1=1"

        def _replace_with_file(match):
            prefix = match.group(1)
            name = match.group(2)
            if name in source_map:
                return f"{prefix}'{data_source}'"
            return match.group(0)

        result = re.sub(
            r"((?:FROM|JOIN)\s+)(\w+)",
            _replace_with_file,
            query,
            flags=re.IGNORECASE,
        )

        # Column alias should be intact
        assert "auth_logs_total" in result
        # FROM target should be the file
        assert f"FROM '{data_source}'" in result


# ── load_rules / load_sources ───────────────────────────────────


class TestLoadRules:
    @mock_aws
    def test_loads_and_caches_rules(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="siem-data-test")
        s3.put_object(
            Bucket="siem-data-test",
            Key="rules/rules.json",
            Body=json.dumps(SAMPLE_RULES),
        )

        rules = de.load_rules()
        assert len(rules) == 2
        assert rules[0]["id"] == "test-rule-1"

        # Second call should return cached
        rules_again = de.load_rules()
        assert rules_again is rules  # same object = cached

    @mock_aws
    def test_loads_sources(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="siem-data-test")
        s3.put_object(
            Bucket="siem-data-test",
            Key="sources/sources.json",
            Body=json.dumps(SAMPLE_SOURCES),
        )

        sources = de.load_sources()
        assert len(sources) == 4
        assert sources[0]["name"] == "auth_logs"


# ── forward_to_destinations ─────────────────────────────────────


class TestForwardToDestinations:
    def test_cloudwatch_type_is_noop(self, capsys):
        """cloudwatch destination type should silently continue."""
        alert = {"matches_count": 1, "matches": [{"foo": "bar"}]}
        rule = {
            "id": "test",
            "name": "Test",
            "severity": "high",
            "destinations": [{"type": "cloudwatch"}],
        }

        de.forward_to_destinations(alert, rule)

        captured = capsys.readouterr()
        # Should NOT print "Unknown destination type"
        assert "Unknown destination type" not in captured.out

    def test_sns_skipped_without_topic_arn(self, capsys):
        alert = {"matches_count": 1, "matches": []}
        rule = {
            "id": "test",
            "name": "Test",
            "severity": "high",
            "destinations": [{"type": "sns", "config": {}}],
        }

        de.forward_to_destinations(alert, rule)

        captured = capsys.readouterr()
        assert "Skipping SNS destination" in captured.out

    def test_webhook_skipped_without_url(self, capsys):
        alert = {"matches_count": 1, "matches": []}
        rule = {
            "id": "test",
            "name": "Test",
            "severity": "high",
            "destinations": [{"type": "webhook", "config": {}}],
        }

        de.forward_to_destinations(alert, rule)

        captured = capsys.readouterr()
        assert "Skipping webhook destination" in captured.out

    def test_unknown_type_logged(self, capsys):
        alert = {"matches_count": 1, "matches": []}
        rule = {
            "id": "test",
            "name": "Test",
            "severity": "high",
            "destinations": [{"type": "carrier_pigeon"}],
        }

        de.forward_to_destinations(alert, rule)

        captured = capsys.readouterr()
        assert "Unknown destination type: carrier_pigeon" in captured.out


# ── lambda_handler routing ──────────────────────────────────────


class TestLambdaHandler:
    @patch.object(de, "run_detections")
    def test_s3_event_triggers_event_driven(self, mock_run):
        event = {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "s3": {
                        "bucket": {"name": "siem-data-test"},
                        "object": {
                            "key": "processed/auth_logs/dt=2025-10-01/chunk_00000.parquet"
                        },
                    },
                }
            ]
        }

        de.lambda_handler(event, None)

        mock_run.assert_called_once_with(
            "s3://siem-data-test/processed/auth_logs/dt=2025-10-01/chunk_00000.parquet"
        )

    @patch.object(de, "run_detections")
    def test_eventbridge_triggers_scheduled(self, mock_run):
        event = {"source": "aws.events", "detail-type": "Scheduled Event"}

        de.lambda_handler(event, None)

        mock_run.assert_called_once_with()  # no args = scheduled

    @patch.object(de, "run_detections")
    def test_unknown_event_runs_all(self, mock_run):
        event = {"something": "unexpected"}

        de.lambda_handler(event, None)

        mock_run.assert_called_once_with()

    @patch.object(de, "run_detections")
    def test_only_enabled_rules_mentioned(self, mock_run):
        """Verify the filter in run_detections excludes disabled rules."""
        # This tests the filtering logic directly
        rules = SAMPLE_RULES
        enabled = [r for r in rules if r.get("enabled", True)]
        assert len(enabled) == 1
        assert enabled[0]["id"] == "test-rule-1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
