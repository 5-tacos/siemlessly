import typer
import boto3
import json
import click
from typing import Optional
import duckdb


app = typer.Typer(help="SIEMlessly CLI - query logs and view alerts")
query_app = typer.Typer(help="Query parsed logs from S3")
alerts_app = typer.Typer(help="View alerts from CloudWatch Logs")
sources_app = typer.Typer(help="Manage data sources")
app.add_typer(query_app, name="query")
app.add_typer(alerts_app, name="alerts")
app.add_typer(sources_app, name="sources")

ALERTS_LOG_GROUP = "/siemlessly/alerts"
SOURCES_S3_KEY = "sources/sources.json"


def setup_duckdb():
    con = duckdb.connect(database=":memory:", read_only=False)
    con.execute("INSTALL httpfs;")
    con.execute("LOAD httpfs;")
    con.execute("INSTALL aws;")
    con.execute("LOAD aws;")
    con.execute("CALL load_aws_credentials();")
    return con


def get_s3_client():
    return boto3.client("s3")


def resolve_source(query: str, bucket: str) -> str:
    """Replace source names in query with full S3 paths.

    Matches bare (unquoted) identifiers after FROM/JOIN keywords that
    correspond to known source names and wraps them in the resolved
    S3 path.  Quoted strings and other identifiers are left alone.
    """
    import re

    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=SOURCES_S3_KEY)
    sources = json.loads(response["Body"].read().decode("utf-8"))
    source_map = {s["name"]: s for s in sources}

    def replace_source(match):
        prefix = match.group(1)  # FROM/JOIN keyword + whitespace
        name = match.group(2)
        if name in source_map:
            path = source_map[name]["parquet_path"].replace("{bucket}", bucket)
            return f"{prefix}'{path}'"
        return match.group(0)

    # Match bare identifiers after FROM or JOIN (case-insensitive)
    resolved = re.sub(
        r"((?:FROM|JOIN)\s+)(\w+)",
        replace_source,
        query,
        flags=re.IGNORECASE,
    )
    return resolved


# ============================================================
# Query commands
# ============================================================


@query_app.command("run")
def run_query(
    query: str = typer.Argument(
        ..., help="SQL query with source names (e.g. SELECT * FROM web_logs)"
    ),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """Execute a SQL query against Parquet files in S3 using source names."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    resolved = resolve_source(query, bucket)
    con = setup_duckdb()

    print(f"Resolved query for s3://{bucket}/...")
    print(resolved)
    print("-" * 60)

    result = con.execute(resolved).fetchdf()

    if output == "json":
        records = result.to_dict(orient="records")
        click.echo(json.dumps(records, indent=2, default=str))
    else:
        click.echo(result.to_string(index=False, max_rows=100))

    click.echo(f"\n{len(result)} rows returned.")


@query_app.command("schema")
def get_schema(
    parquet_path: str = typer.Argument(
        ..., help="S3 path to Parquet file (e.g. s3://bucket/processed/...)"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """Show schema of a Parquet file in S3."""
    con = setup_duckdb()

    result = con.execute(f"DESCRIBE SELECT * FROM '{parquet_path}'").fetchdf()

    if output == "json":
        click.echo(json.dumps(result.to_dict(orient="records"), indent=2))
    else:
        click.echo(f"Schema for: {parquet_path}")
        click.echo("-" * 60)
        click.echo(result.to_string(index=False))


# ============================================================
# Sources commands
# ============================================================


@sources_app.command("list")
def list_sources(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """List all data sources."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=SOURCES_S3_KEY)
    sources = json.loads(response["Body"].read().decode("utf-8"))

    if output == "json":
        click.echo(json.dumps(sources, indent=2))
    else:
        click.echo(f"{'Name':<20} {'Description':<40} {'Parquet Path'}")
        click.echo("-" * 80)
        for s in sources:
            click.echo(
                f"{s['name']:<20} {s.get('description', ''):<40} {s['parquet_path']}"
            )


@sources_app.command("get")
def get_source(
    name: str = typer.Argument(..., help="Source name"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Get a specific source definition."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=SOURCES_S3_KEY)
    sources = json.loads(response["Body"].read().decode("utf-8"))

    for s in sources:
        if s["name"] == name:
            click.echo(json.dumps(s, indent=2))
            return

    click.echo(f"Source '{name}' not found.", err=True)
    raise typer.Exit(code=1)


@sources_app.command("create")
def create_source(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Create a new source definition."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    click.echo("Enter source details (or Ctrl+C to cancel):")
    name = click.prompt("Name")
    description = click.prompt("Description", default="", show_default=False)
    parquet_path = click.prompt("Parquet path (use {bucket} for bucket placeholder)")
    raw_path = click.prompt(
        "Raw log path (optional, use {bucket})", default="", show_default=False
    )

    source = {
        "name": name,
        "description": description if description else None,
        "parquet_path": parquet_path,
        "raw_path": raw_path if raw_path else None,
    }

    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=SOURCES_S3_KEY)
    sources = json.loads(response["Body"].read().decode("utf-8"))

    for s in sources:
        if s["name"] == name:
            click.echo(f"Source '{name}' already exists.", err=True)
            raise typer.Exit(code=1)

    sources.append(source)
    s3.put_object(Bucket=bucket, Key=SOURCES_S3_KEY, Body=json.dumps(sources, indent=2))
    click.echo(f"Source '{name}' created successfully.")


@sources_app.command("delete")
def delete_source(
    name: str = typer.Argument(..., help="Source name"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Delete a source definition."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=SOURCES_S3_KEY)
    sources = json.loads(response["Body"].read().decode("utf-8"))

    new_sources = [s for s in sources if s["name"] != name]

    if len(new_sources) == len(sources):
        click.echo(f"Source '{name}' not found.", err=True)
        raise typer.Exit(code=1)

    s3.put_object(
        Bucket=bucket, Key=SOURCES_S3_KEY, Body=json.dumps(new_sources, indent=2)
    )
    click.echo(f"Source '{name}' deleted successfully.")


# ============================================================
# Alerts commands
# ============================================================


@alerts_app.command("list")
def list_alerts(
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Filter by severity"
    ),
    rule_id: Optional[str] = typer.Option(
        None, "--rule", "-r", help="Filter by rule ID"
    ),
    days: int = typer.Option(7, "--days", "-d", help="Number of days to look back"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max number of alerts"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """List alerts from CloudWatch Logs."""
    logs = boto3.client("logs")

    all_alerts = []
    for i in range(days):
        log_stream_prefix = f"rule-{rule_id}/" if rule_id else "rule-"
        try:
            streams = logs.describe_log_streams(
                logGroupName=ALERTS_LOG_GROUP,
                logStreamNamePrefix=log_stream_prefix,
                orderBy="LastEventTime",
                descending=True,
                limit=100,
            )
        except Exception:
            continue

        for stream in streams.get("logStreams", []):
            stream_name = stream["logStreamName"]
            if rule_id and not stream_name.startswith(f"rule-{rule_id}/"):
                continue
            try:
                events = logs.get_log_events(
                    logGroupName=ALERTS_LOG_GROUP,
                    logStreamName=stream_name,
                    limit=1000,
                )
                for event in events.get("events", []):
                    alert = json.loads(event["message"])
                    all_alerts.append(alert)
            except Exception:
                continue

    if severity:
        all_alerts = [a for a in all_alerts if a.get("severity") == severity]

    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_alerts = all_alerts[:limit]

    if output == "json":
        click.echo(json.dumps(all_alerts, indent=2, default=str))
    else:
        if not all_alerts:
            click.echo("No alerts found.")
            return

        click.echo(f"{'Timestamp':<28} {'Rule':<30} {'Severity':<12} {'Matches':<8}")
        click.echo("-" * 78)
        for alert in all_alerts:
            ts = alert.get("timestamp", "N/A")[:19]
            click.echo(
                f"{str(ts):<28} {alert.get('rule_name', 'N/A'):<30} {alert.get('severity', 'N/A'):<12} {alert.get('matches_count', 0):<8}"
            )


@alerts_app.command("get")
def get_alert(
    rule_id: str = typer.Argument(..., help="Rule ID that triggered the alert"),
    days: int = typer.Option(7, "--days", "-d", help="Number of days to look back"),
    limit: int = typer.Option(10, "--limit", "-l", help="Max number of alerts"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """Get detailed alerts for a specific rule."""
    logs = boto3.client("logs")

    all_alerts = []
    log_stream_prefix = f"rule-{rule_id}/"

    try:
        streams = logs.describe_log_streams(
            logGroupName=ALERTS_LOG_GROUP,
            logStreamNamePrefix=log_stream_prefix,
            orderBy="LastEventTime",
            descending=True,
            limit=100,
        )
    except Exception:
        click.echo(f"No log streams found for rule '{rule_id}'.", err=True)
        raise typer.Exit(code=1)

    for stream in streams.get("logStreams", []):
        stream_name = stream["logStreamName"]
        if not stream_name.startswith(f"rule-{rule_id}/"):
            continue
        try:
            events = logs.get_log_events(
                logGroupName=ALERTS_LOG_GROUP,
                logStreamName=stream_name,
                limit=1000,
            )
            for event in events.get("events", []):
                alert = json.loads(event["message"])
                all_alerts.append(alert)
        except Exception:
            continue

    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_alerts = all_alerts[:limit]

    if output == "json":
        click.echo(json.dumps(all_alerts, indent=2, default=str))
    else:
        if not all_alerts:
            click.echo(f"No alerts found for rule '{rule_id}'.")
            return

        for alert in all_alerts:
            click.echo(f"\n--- Alert: {alert.get('rule_name', 'N/A')} ---")
            click.echo(f"Severity: {alert.get('severity', 'N/A')}")
            click.echo(f"Matches: {alert.get('matches_count', 0)}")
            click.echo(f"Timestamp: {alert.get('timestamp', 'N/A')}")
            if alert.get("matches"):
                click.echo("Sample matches:")
                for match in alert["matches"][:3]:
                    click.echo(json.dumps(match, indent=4, default=str))
            click.echo("-" * 40)


if __name__ == "__main__":
    app()
