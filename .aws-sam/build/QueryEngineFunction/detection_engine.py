import os
import json
import re
import duckdb
import boto3
import time
from datetime import datetime, timezone

# Initialize globally
con = duckdb.connect(database=":memory:", read_only=False)
sns_client = boto3.client("sns")
logs_client = boto3.client("logs")

S3_BUCKET = os.environ.get("S3_BUCKET")
SOURCES_S3_KEY = "sources/sources.json"
ALERTS_LOG_GROUP = os.environ.get("ALERTS_LOG_GROUP", "/siemlessly/alerts")
RULES_S3_KEY = "rules/rules.json"
RULES_CACHE_TTL = int(os.environ.get("RULES_CACHE_TTL", "300"))
SOURCES_CACHE_TTL = int(os.environ.get("SOURCES_CACHE_TTL", "600"))

# Cache for rules loaded from S3
_rule_cache = None
_rule_cache_time = 0

# Cache for sources loaded from S3
_source_cache = None
_source_cache_time = 0


def load_sources():
    """Load data sources from S3 with TTL-based caching."""
    global _source_cache, _source_cache_time

    now = time.time()
    if _source_cache and (now - _source_cache_time) < SOURCES_CACHE_TTL:
        return _source_cache

    s3_client = boto3.client("s3")
    response = s3_client.get_object(Bucket=S3_BUCKET, Key=SOURCES_S3_KEY)
    content = response["Body"].read().decode("utf-8")
    sources = json.loads(content)

    _source_cache = sources
    _source_cache_time = now

    print(f"Loaded {len(sources)} data sources from S3")
    return sources


def resolve_source_names(query: str) -> str:
    """Replace source names in query with full S3 paths.

    Matches bare (unquoted) identifiers after FROM/JOIN keywords that
    correspond to known source names and wraps them in the resolved
    S3 path.  Quoted strings and other identifiers are left alone.
    """
    sources = load_sources()
    source_map = {s["name"]: s for s in sources}

    def replace_source(match):
        prefix = match.group(1)  # FROM/JOIN keyword + whitespace
        name = match.group(2)
        if name in source_map:
            path = source_map[name]["parquet_path"].replace("{bucket}", S3_BUCKET)
            return f"{prefix}'{path}'"
        return match.group(0)

    # Match bare identifiers after FROM or JOIN (case-insensitive)
    return re.sub(
        r"((?:FROM|JOIN)\s+)(\w+)",
        replace_source,
        query,
        flags=re.IGNORECASE,
    )


def load_rules():
    """Load detection rules from S3 with TTL-based caching."""
    global _rule_cache, _rule_cache_time

    now = time.time()
    if _rule_cache and (now - _rule_cache_time) < RULES_CACHE_TTL:
        return _rule_cache

    s3_client = boto3.client("s3")
    response = s3_client.get_object(Bucket=S3_BUCKET, Key=RULES_S3_KEY)
    content = response["Body"].read().decode("utf-8")
    rules = json.loads(content)

    _rule_cache = rules
    _rule_cache_time = now

    print(f"Loaded {len(rules)} detection rules from S3")
    return rules


_duckdb_ready = False


def setup_duckdb():
    global _duckdb_ready
    if _duckdb_ready:
        return
    con.execute("INSTALL httpfs;")
    con.execute("LOAD httpfs;")
    con.execute("INSTALL aws;")
    con.execute("LOAD aws;")
    con.execute("CALL load_aws_credentials();")
    _duckdb_ready = True


def write_alert_to_cloudwatch(alert, rule):
    """Write alert to CloudWatch Logs."""
    log_stream_name = (
        f"rule-{rule['id']}/{datetime.now(timezone.utc).strftime('%Y%m%d')}"
    )

    # Ensure log stream exists before writing events
    try:
        logs_client.create_log_stream(
            logGroupName=ALERTS_LOG_GROUP,
            logStreamName=log_stream_name,
        )
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass

    timestamp = datetime.now(timezone.utc)
    ts_ms = int(timestamp.timestamp() * 1000)

    log_entry = json.dumps(
        {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "matches_count": alert["matches_count"],
            "timestamp": timestamp.isoformat(),
            "matches": alert["matches"],
        }
    )

    try:
        logs_client.put_log_events(
            logGroupName=ALERTS_LOG_GROUP,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": ts_ms, "message": log_entry}],
        )
    except Exception as e:
        print(f"Error writing alert to CloudWatch: {e}")


def forward_to_destinations(alert, rule):
    """Forward alert to destinations defined inline in the rule."""
    destinations = rule.get("destinations", [])
    if not destinations:
        return

    for dest in destinations:
        dest_type = dest.get("type")
        config = dest.get("config", {})

        try:
            if dest_type == "cloudwatch":
                # CloudWatch is always written via write_alert_to_cloudwatch;
                # listing it in destinations is declarative — nothing extra to do.
                continue
            elif dest_type == "sns":
                topic_arn = config.get("topic_arn")
                if not topic_arn:
                    print(f"Skipping SNS destination: no topic_arn configured")
                    continue
                sns_client.publish(
                    TopicArn=topic_arn,
                    Subject=f"SIEM Alert: {rule['name']} [{rule['severity'].upper()}]",
                    Message=json.dumps(alert, indent=2, default=str),
                )
                print(f"Forwarded alert to SNS destination")
            elif dest_type == "webhook":
                webhook_url = config.get("url")
                if not webhook_url:
                    print(f"Skipping webhook destination: no url configured")
                    continue
                import urllib.request

                req = urllib.request.Request(
                    webhook_url,
                    data=json.dumps({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "matches_count": alert["matches_count"],
                        "matches": alert["matches"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }, default=str).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
                print(f"Forwarded alert to webhook destination")
            else:
                print(f"Unknown destination type: {dest_type}")
        except Exception as e:
            print(f"Error forwarding to destination '{dest_type}': {e}")


def publish_alert(rule, matches):
    """Publish an alert to CloudWatch and forward to configured destinations."""
    alert = {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "matches_count": len(matches),
        "matches": matches[:10],
    }

    print(f"ALERT TRIGGERED [{rule['severity'].upper()}]: {rule['name']}")
    print(json.dumps(alert, default=str))

    # Always write to CloudWatch Logs
    write_alert_to_cloudwatch(alert, rule)

    # Forward to configured destinations
    forward_to_destinations(alert, rule)


def run_detections(data_source=None):
    """Run all detection rules.

    Args:
        data_source: Optional S3 URI to a specific file. When provided
            (event-driven mode), source name references in queries are
            replaced with this path so the rule only scans the new file.
            When ``None`` (scheduled mode), source names resolve to
            the full glob defined in sources.json.
    """
    setup_duckdb()
    print(f"Running detections against source: {data_source or 'all (scheduled)'}")

    rules = load_rules()
    enabled_rules = [r for r in rules if r.get("enabled", True)]
    print(f"Running {len(enabled_rules)} enabled rules")

    for rule in enabled_rules:
        try:
            if data_source:
                # Event-driven: replace source names with the specific file.
                # Uses regex to only match bare identifiers after FROM/JOIN,
                # avoiding corruption of column names or string literals.
                sources = load_sources()
                source_map = {s["name"] for s in sources}

                def _replace_with_file(match):
                    prefix = match.group(1)
                    name = match.group(2)
                    if name in source_map:
                        return f"{prefix}'{data_source}'"
                    return match.group(0)

                target_query = re.sub(
                    r"((?:FROM|JOIN)\s+)(\w+)",
                    _replace_with_file,
                    rule["query"],
                    flags=re.IGNORECASE,
                )
            else:
                # Scheduled: resolve to full source paths
                target_query = resolve_source_names(rule["query"])

            print(f"Executing rule {rule['id']} -> {target_query}")

            result = con.execute(target_query).fetchdf()
            matches = result.to_dict(orient="records")

            if len(matches) > 0:
                publish_alert(rule, matches)

        except Exception as e:
            print(f"Error running rule {rule['id']}: {e}")


def lambda_handler(event, context):
    """
    Handles both EventBridge (Scheduled) and S3 (Event-Driven) triggers.
    """
    print(f"Received event: {json.dumps(event)}")

    # Check if this is an S3 Event (Event-Driven)
    if "Records" in event and event["Records"][0].get("eventSource") == "aws:s3":
        print("Handling S3 ObjectCreated Event (Near Real-Time Detection)")
        for record in event["Records"]:
            bucket = record["s3"]["bucket"]["name"]
            key = record["s3"]["object"]["key"]

            # The newly uploaded Parquet file
            new_file_s3_uri = f"s3://{bucket}/{key}"

            # Run detections ONLY against this new file
            run_detections(new_file_s3_uri)

    # Check if this is an EventBridge Event (Scheduled)
    elif (
        event.get("source") == "aws.events"
        or event.get("source") == "ScheduledDetection"
    ):
        print("Handling EventBridge Scheduled Event (Batch Detection)")
        run_detections()  # No data_source = resolve full source paths

    else:
        print("Unknown event source. Assuming ad-hoc run against all data.")
        run_detections()

    return {"statusCode": 200, "body": "Detections completed successfully."}
