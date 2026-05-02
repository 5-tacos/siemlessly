"""
Ingestion pipeline: streams raw log files from S3, classifies events by type,
and writes date-partitioned Parquet datasets per event type.

Supports two input formats:
  - .jsonl.gz  (gzipped NDJSON — the actual dataset format)
  - .tar.gz    (tarball containing .json files — legacy/backward compat)

Output layout:
  processed/<event_type>/dt=YYYY-MM-DD/chunk_NNNNN.parquet
"""

import os
import sys
import json
import gzip
import tarfile
import boto3
import pyarrow as pa
import pyarrow.parquet as pq
from io import BytesIO
from urllib.parse import urlparse
from collections import defaultdict

S3_BUCKET = os.environ.get("S3_BUCKET", "siem-data-local")
s3_client = boto3.client("s3")

BATCH_SIZE = 100_000  # rows per chunk per event type

# ---------------------------------------------------------------------------
# Event-type classification
# ---------------------------------------------------------------------------
# Each event type has unique discriminating fields. Order matters:
# check rarer/more specific types first to avoid misclassification.
# ---------------------------------------------------------------------------

def classify_event(record: dict) -> str:
    """Classify a JSON record into one of the 7 known event types."""
    if "vpn_endpoint" in record or ("event_type" in record and record.get("event_id", "").startswith("vpn-")):
        return "vpn_logs"
    if "patient_id" in record or record.get("event_id", "").startswith("ehr-"):
        return "ehr_access"
    if "auth_method" in record or record.get("event_id", "").startswith("auth-"):
        return "auth_logs"
    if "http_method" in record:
        return "http_logs"
    if "query_type" in record:
        return "db_queries"
    if "event_source" in record:
        return "cloudtrail"
    if "destination_ip" in record:
        return "network_flows"
    return "unknown"


# ---------------------------------------------------------------------------
# Schema definitions — one per event type.
# Nested objects (identity, geo, user_identity, etc.) are serialized to JSON
# strings so DuckDB can query them with ->> / json_extract().
# ---------------------------------------------------------------------------

SCHEMAS = {
    "http_logs": pa.schema([
        ("timestamp", pa.string()),
        ("request_id", pa.string()),
        ("source_ip", pa.string()),
        ("http_method", pa.string()),
        ("path", pa.string()),
        ("status_code", pa.int32()),
        ("response_time_ms", pa.int32()),
        ("request_size_bytes", pa.int64()),
        ("response_size_bytes", pa.int64()),
        ("user_agent", pa.string()),
        ("identity", pa.string()),       # JSON string: {type, service|employee_id, ...}
        ("api_version", pa.string()),
    ]),
    "db_queries": pa.schema([
        ("timestamp", pa.string()),
        ("query_id", pa.string()),
        ("source_service", pa.string()),
        ("query_type", pa.string()),
        ("table_name", pa.string()),
        ("execution_time_ms", pa.int32()),
        ("rows_returned", pa.int64()),
        ("rows_affected", pa.int64()),
        ("parameters", pa.string()),      # JSON string
        ("correlated_request_id", pa.string()),
        ("database", pa.string()),
        ("employee_id", pa.string()),
    ]),
    "cloudtrail": pa.schema([
        ("timestamp", pa.string()),
        ("event_id", pa.string()),
        ("event_source", pa.string()),
        ("event_name", pa.string()),
        ("aws_region", pa.string()),
        ("source_ip", pa.string()),
        ("user_identity", pa.string()),    # JSON string: {type, arn, session_name}
        ("request_parameters", pa.string()),  # JSON string
        ("response_elements", pa.string()),   # JSON string
        ("error_code", pa.string()),
        ("read_only", pa.bool_()),
    ]),
    "network_flows": pa.schema([
        ("timestamp", pa.string()),
        ("event_id", pa.string()),
        ("event_type", pa.string()),
        ("source_ip", pa.string()),
        ("destination_ip", pa.string()),
        ("source_port", pa.int32()),
        ("destination_port", pa.int32()),
        ("protocol", pa.string()),
        ("bytes_sent", pa.int64()),
        ("bytes_received", pa.int64()),
        ("duration_seconds", pa.float64()),
        ("employee_id", pa.string()),
        ("geo", pa.string()),              # JSON string: {city, state, country}
    ]),
    "ehr_access": pa.schema([
        ("timestamp", pa.string()),
        ("event_id", pa.string()),
        ("employee_id", pa.string()),
        ("patient_id", pa.string()),
        ("action", pa.string()),
        ("record_type", pa.string()),
        ("access_reason", pa.string()),
        ("department", pa.string()),
        ("source_ip", pa.string()),
        ("session_id", pa.string()),
        ("duration_seconds", pa.float64()),
        ("records_returned", pa.int64()),
    ]),
    "auth_logs": pa.schema([
        ("timestamp", pa.string()),
        ("event_id", pa.string()),
        ("employee_id", pa.string()),
        ("event_type", pa.string()),
        ("auth_method", pa.string()),
        ("mfa_type", pa.string()),
        ("source_ip", pa.string()),
        ("user_agent", pa.string()),
        ("geo", pa.string()),              # JSON string: {city, state, country}
        ("session_id", pa.string()),
        ("risk_score", pa.float64()),
        ("success", pa.bool_()),
    ]),
    "vpn_logs": pa.schema([
        ("timestamp", pa.string()),
        ("event_id", pa.string()),
        ("employee_id", pa.string()),
        ("event_type", pa.string()),
        ("source_ip", pa.string()),
        ("vpn_endpoint", pa.string()),
        ("assigned_ip", pa.string()),
        ("protocol", pa.string()),
        ("bytes_sent", pa.int64()),
        ("bytes_received", pa.int64()),
        ("duration_seconds", pa.float64()),
        ("geo", pa.string()),              # JSON string: {city, state, country}
    ]),
}


def normalize_record(record: dict, event_type: str) -> dict:
    """Normalize a raw JSON record to match the declared schema.

    - Serializes nested objects (dicts/lists) to JSON strings.
    - Ensures all declared fields are present (fills None for missing).
    - Drops any extra fields not in the schema.
    """
    schema = SCHEMAS.get(event_type)
    if schema is None:
        return record

    normalized = {}
    for field in schema:
        val = record.get(field.name)
        # Serialize nested objects to JSON strings
        if isinstance(val, (dict, list)):
            val = json.dumps(val)
        normalized[field.name] = val

    return normalized


# ---------------------------------------------------------------------------
# Parquet writing
# ---------------------------------------------------------------------------

class ParquetWriter:
    """Manages per-event-type, per-date chunk writing to S3."""

    def __init__(self, bucket: str):
        self.bucket = bucket
        # buffers[event_type][date_str] = list of normalized dicts
        self.buffers = defaultdict(lambda: defaultdict(list))
        # chunk_index[event_type][date_str] = int
        self.chunk_index = defaultdict(lambda: defaultdict(int))
        self.stats = defaultdict(int)

    def add(self, record: dict, event_type: str):
        """Add a classified, normalized record to the buffer."""
        ts = record.get("timestamp", "")
        date_str = ts[:10] if len(ts) >= 10 else "unknown"

        self.buffers[event_type][date_str].append(record)
        self.stats[event_type] += 1

        if len(self.buffers[event_type][date_str]) >= BATCH_SIZE:
            self.flush(event_type, date_str)

    def flush(self, event_type: str, date_str: str):
        """Write one chunk to S3 and clear the buffer."""
        rows = self.buffers[event_type][date_str]
        if not rows:
            return

        schema = SCHEMAS.get(event_type)
        if schema:
            table = pa.Table.from_pylist(rows, schema=schema)
        else:
            table = pa.Table.from_pylist(rows)

        buf = BytesIO()
        pq.write_table(table, buf, compression="snappy")
        buf.seek(0)

        idx = self.chunk_index[event_type][date_str]
        key = f"processed/{event_type}/dt={date_str}/chunk_{idx:05d}.parquet"

        s3_client.put_object(Bucket=self.bucket, Key=key, Body=buf.getvalue())
        print(f"  ↳ wrote {len(rows):,} rows → s3://{self.bucket}/{key}")

        self.chunk_index[event_type][date_str] += 1
        rows.clear()

    def flush_all(self):
        """Flush every remaining buffer."""
        for event_type in list(self.buffers):
            for date_str in list(self.buffers[event_type]):
                self.flush(event_type, date_str)

    def print_stats(self):
        total = sum(self.stats.values())
        print(f"\n{'='*50}")
        print(f"Ingestion complete — {total:,} events classified:")
        for et in sorted(self.stats, key=self.stats.get, reverse=True):
            print(f"  {et:20s}: {self.stats[et]:>10,}")
        print(f"{'='*50}\n")


# ---------------------------------------------------------------------------
# File processing — supports .jsonl.gz and .tar.gz
# ---------------------------------------------------------------------------

def process_jsonl_gz(bucket: str, key: str, writer: ParquetWriter):
    """Stream a .jsonl.gz file from S3, classify events, write partitioned Parquet."""
    print(f"Streaming s3://{bucket}/{key} (jsonl.gz mode)")

    response = s3_client.get_object(Bucket=bucket, Key=key)
    body = response["Body"]

    line_count = 0
    error_count = 0

    with gzip.open(body, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                error_count += 1
                continue

            event_type = classify_event(record)
            normalized = normalize_record(record, event_type)
            writer.add(normalized, event_type)

            line_count += 1
            if line_count % 500_000 == 0:
                print(f"  processed {line_count:,} lines...")

    writer.flush_all()

    print(f"  finished {key}: {line_count:,} events, {error_count} parse errors")


def process_tarball(bucket: str, key: str, writer: ParquetWriter):
    """Stream a .tar.gz from S3, extract JSON files, classify events."""
    print(f"Streaming s3://{bucket}/{key} (tar.gz mode)")

    response = s3_client.get_object(Bucket=bucket, Key=key)

    with tarfile.open(fileobj=response["Body"], mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            if not (member.name.endswith(".json") or member.name.endswith(".jsonl")):
                continue

            print(f"  extracting: {member.name}")
            f = tar.extractfile(member)
            if not f:
                continue

            for line in f:
                try:
                    record = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue

                event_type = classify_event(record)
                normalized = normalize_record(record, event_type)
                writer.add(normalized, event_type)

    writer.flush_all()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def process_file(bucket: str, key: str):
    """Dispatch to the correct processor based on file extension."""
    writer = ParquetWriter(bucket)

    if key.endswith(".jsonl.gz") or key.endswith(".ndjson.gz"):
        process_jsonl_gz(bucket, key, writer)
    elif key.endswith(".tar.gz") or key.endswith(".tgz"):
        process_tarball(bucket, key, writer)
    else:
        print(f"WARNING: unknown file format for {key}, attempting jsonl.gz")
        process_jsonl_gz(bucket, key, writer)

    writer.print_stats()


if __name__ == "__main__":
    target_s3_url = os.environ.get("TARGET_S3_URL")
    if not target_s3_url:
        print("TARGET_S3_URL environment variable is required.")
        sys.exit(1)

    parsed = urlparse(target_s3_url)
    bucket_name = parsed.netloc
    object_key = parsed.path.lstrip("/")

    process_file(bucket_name, object_key)
