import typer
import boto3
import json
import click
from typing import List, Optional
from pydantic import BaseModel, Field


app = typer.Typer(help="SIEMlessly CLI - detection rules, queries, and alerts")
rules_app = typer.Typer(help="Detection rules management")
destinations_app = typer.Typer(help="Alert destination management")
alerts_app = typer.Typer(help="Alert viewing")
app.add_typer(rules_app, name="rules")
app.add_typer(destinations_app, name="destinations")
app.add_typer(alerts_app, name="alerts")

S3_RULES_KEY = "rules/rules.json"
S3_DESTINATIONS_KEY = "destinations/destinations.json"
ALERTS_LOG_GROUP = "/siemlessly/alerts"


class Rule(BaseModel):
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    description: Optional[str] = Field(None, description="Rule description")
    query: str = Field(..., description="SQL query with {data_source} placeholder")
    severity: str = Field(..., description="Rule severity: low, medium, high, critical")
    enabled: bool = Field(True, description="Whether the rule is enabled")


class Destination(BaseModel):
    id: str = Field(..., description="Unique destination identifier")
    name: str = Field(..., description="Human-readable destination name")
    type: str = Field(..., description="Destination type: sns, webhook")
    config: dict = Field(..., description="Destination-specific config")
    enabled: bool = Field(True, description="Whether the destination is enabled")


def get_s3_client():
    return boto3.client("s3")


def get_logs_client():
    return boto3.client("logs")


def load_from_s3(bucket: str, key: str) -> list:
    s3 = get_s3_client()
    response = s3.get_object(Bucket=bucket, Key=key)
    content = response["Body"].read().decode("utf-8")
    return json.loads(content)


def save_to_s3(bucket: str, key: str, data: list) -> None:
    s3 = get_s3_client()
    content = json.dumps(data, indent=2)
    s3.put_object(Bucket=bucket, Key=key, Body=content)


def print_rules(rules: List[dict]) -> None:
    if not rules:
        click.echo("No rules found.")
        return

    click.echo(f"{'ID':<20} {'Name':<40} {'Severity':<12} {'Enabled':<8}")
    click.echo("-" * 80)
    for rule in rules:
        click.echo(
            f"{rule['id']:<20} {rule['name']:<40} {rule['severity']:<12} {str(rule.get('enabled', True)):<8}"
        )


def print_destinations(destinations: List[dict]) -> None:
    if not destinations:
        click.echo("No destinations found.")
        return

    click.echo(f"{'ID':<20} {'Name':<30} {'Type':<10} {'Enabled':<8}")
    click.echo("-" * 68)
    for dest in destinations:
        click.echo(
            f"{dest['id']:<20} {dest['name']:<30} {dest['type']:<10} {str(dest.get('enabled', True)):<8}"
        )


# ============================================================
# Rules commands
# ============================================================


@rules_app.command("list")
def list_rules(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """List all detection rules."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    if output == "json":
        click.echo(json.dumps(rules, indent=2))
    else:
        print_rules(rules)


@rules_app.command("get")
def get_rule(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Get a specific rule by ID."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)
    for rule in rules:
        if rule["id"] == rule_id:
            click.echo(json.dumps(rule, indent=2))
            return

    click.echo(f"Rule '{rule_id}' not found.", err=True)
    raise typer.Exit(code=1)


@rules_app.command("create")
def create_rule(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Rule definition file (JSON)"
    ),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", "-i/-n", help="Interactive mode"
    ),
):
    """Create a new detection rule."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    if file:
        with open(file, "r") as f:
            rule_data = json.load(f)
        rule = Rule(**rule_data)
    elif interactive:
        click.echo("Enter rule details (or Ctrl+C to cancel):")
        rule_id = click.prompt("Rule ID")
        rule_name = click.prompt("Rule name")
        rule_desc = click.prompt("Description", default="", show_default=False)
        rule_query = click.prompt("Query")
        rule_severity = click.prompt(
            "Severity (low/medium/high/critical)", default="medium"
        )
        rule = Rule(
            id=rule_id,
            name=rule_name,
            description=rule_desc if rule_desc else None,
            query=rule_query,
            severity=rule_severity,
        )
    else:
        click.echo(
            "Provide a file with --file or use --interactive (default).", err=True
        )
        raise typer.Exit(code=1)

    rules = load_from_s3(bucket, S3_RULES_KEY)

    for r in rules:
        if r["id"] == rule.id:
            click.echo(f"Rule with ID '{rule.id}' already exists.", err=True)
            raise typer.Exit(code=1)

    rules.append(rule.model_dump())
    save_to_s3(bucket, S3_RULES_KEY, rules)
    click.echo(f"Rule '{rule.id}' created successfully.")


@rules_app.command("update")
def update_rule(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    name: Optional[str] = typer.Option(None, "--name", help="New name"),
    query: Optional[str] = typer.Option(None, "--query", help="New query"),
    severity: Optional[str] = typer.Option(None, "--severity", help="New severity"),
    file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Full rule definition file (JSON)"
    ),
):
    """Update an existing detection rule."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    for i, rule in enumerate(rules):
        if rule["id"] == rule_id:
            if file:
                with open(file, "r") as f:
                    updated = json.load(f)
                rules[i] = updated
            else:
                if name:
                    rules[i]["name"] = name
                if query:
                    rules[i]["query"] = query
                if severity:
                    rules[i]["severity"] = severity
                rules[i]["id"] = rule_id
                rules[i]["enabled"] = rule.get("enabled", True)
                rules[i]["description"] = rule.get("description")

            save_to_s3(bucket, S3_RULES_KEY, rules)
            click.echo(f"Rule '{rule_id}' updated successfully.")
            return

    click.echo(f"Rule '{rule_id}' not found.", err=True)
    raise typer.Exit(code=1)


@rules_app.command("delete")
def delete_rule(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Delete a detection rule."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    new_rules = [r for r in rules if r["id"] != rule_id]

    if len(new_rules) == len(rules):
        click.echo(f"Rule '{rule_id}' not found.", err=True)
        raise typer.Exit(code=1)

    save_to_s3(bucket, S3_RULES_KEY, new_rules)
    click.echo(f"Rule '{rule_id}' deleted successfully.")


@rules_app.command("enable")
def enable_rule(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Enable a detection rule."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    for rule in rules:
        if rule["id"] == rule_id:
            rule["enabled"] = True
            save_to_s3(bucket, S3_RULES_KEY, rules)
            click.echo(f"Rule '{rule_id}' enabled.")
            return

    click.echo(f"Rule '{rule_id}' not found.", err=True)
    raise typer.Exit(code=1)


@rules_app.command("disable")
def disable_rule(
    rule_id: str = typer.Argument(..., help="Rule ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Disable a detection rule."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    for rule in rules:
        if rule["id"] == rule_id:
            rule["enabled"] = False
            save_to_s3(bucket, S3_RULES_KEY, rules)
            click.echo(f"Rule '{rule_id}' disabled.")
            return

    click.echo(f"Rule '{rule_id}' not found.", err=True)
    raise typer.Exit(code=1)


@rules_app.command("upload")
def upload_rules(
    file: str = typer.Argument(..., help="Local rules file (JSON array)"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Upload a local rules file to S3."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    with open(file, "r") as f:
        rules = json.load(f)

    save_to_s3(bucket, S3_RULES_KEY, rules)
    click.echo(f"Uploaded {len(rules)} rules to s3://{bucket}/{S3_RULES_KEY}")


@rules_app.command("download")
def download_rules(
    file: str = typer.Argument(..., help="Local file to write rules to"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Download rules from S3 to a local file."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    rules = load_from_s3(bucket, S3_RULES_KEY)

    with open(file, "w") as f:
        json.dump(rules, f, indent=2)

    click.echo(f"Downloaded {len(rules)} rules to {file}")


# ============================================================
# Destinations commands
# ============================================================


@destinations_app.command("list")
def list_destinations(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output format (table, json)"
    ),
):
    """List all alert destinations."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)

    if output == "json":
        click.echo(json.dumps(destinations, indent=2))
    else:
        print_destinations(destinations)


@destinations_app.command("get")
def get_destination(
    dest_id: str = typer.Argument(..., help="Destination ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Get a specific destination by ID."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)
    for dest in destinations:
        if dest["id"] == dest_id:
            click.echo(json.dumps(dest, indent=2))
            return

    click.echo(f"Destination '{dest_id}' not found.", err=True)
    raise typer.Exit(code=1)


@destinations_app.command("create")
def create_destination(
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", "-i/-n", help="Interactive mode"
    ),
):
    """Create a new alert destination."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    click.echo("Enter destination details (or Ctrl+C to cancel):")
    dest_id = click.prompt("Destination ID")
    dest_name = click.prompt("Name")
    dest_type = click.prompt("Type (sns/webhook)", default="sns")

    config = {}
    if dest_type == "sns":
        topic_arn = click.prompt("SNS Topic ARN")
        config["topic_arn"] = topic_arn
    elif dest_type == "webhook":
        url = click.prompt("Webhook URL")
        config["url"] = url

    dest = Destination(
        id=dest_id,
        name=dest_name,
        type=dest_type,
        config=config,
    )

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)

    for d in destinations:
        if d["id"] == dest.id:
            click.echo(f"Destination with ID '{dest.id}' already exists.", err=True)
            raise typer.Exit(code=1)

    destinations.append(dest.model_dump())
    save_to_s3(bucket, S3_DESTINATIONS_KEY, destinations)
    click.echo(f"Destination '{dest.id}' created successfully.")


@destinations_app.command("delete")
def delete_destination(
    dest_id: str = typer.Argument(..., help="Destination ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Delete an alert destination."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)

    new_destinations = [d for d in destinations if d["id"] != dest_id]

    if len(new_destinations) == len(destinations):
        click.echo(f"Destination '{dest_id}' not found.", err=True)
        raise typer.Exit(code=1)

    save_to_s3(bucket, S3_DESTINATIONS_KEY, new_destinations)
    click.echo(f"Destination '{dest_id}' deleted successfully.")


@destinations_app.command("enable")
def enable_destination(
    dest_id: str = typer.Argument(..., help="Destination ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Enable an alert destination."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)

    for dest in destinations:
        if dest["id"] == dest_id:
            dest["enabled"] = True
            save_to_s3(bucket, S3_DESTINATIONS_KEY, destinations)
            click.echo(f"Destination '{dest_id}' enabled.")
            return

    click.echo(f"Destination '{dest_id}' not found.", err=True)
    raise typer.Exit(code=1)


@destinations_app.command("disable")
def disable_destination(
    dest_id: str = typer.Argument(..., help="Destination ID"),
    bucket: str = typer.Option(None, "--bucket", "-b", help="S3 bucket name"),
):
    """Disable an alert destination."""
    if not bucket:
        bucket = click.prompt("S3 bucket name", default="siem-data")

    destinations = load_from_s3(bucket, S3_DESTINATIONS_KEY)

    for dest in destinations:
        if dest["id"] == dest_id:
            dest["enabled"] = False
            save_to_s3(bucket, S3_DESTINATIONS_KEY, destinations)
            click.echo(f"Destination '{dest_id}' disabled.")
            return

    click.echo(f"Destination '{dest_id}' not found.", err=True)
    raise typer.Exit(code=1)


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
    logs = get_logs_client()

    all_alerts = []
    for i in range(days):
        date_str = f"{(days - i - 1):02d}"
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

    # Apply filters
    if severity:
        all_alerts = [a for a in all_alerts if a.get("severity") == severity]

    # Sort by timestamp (newest first)
    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Limit results
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
    logs = get_logs_client()

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
