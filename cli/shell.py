"""
SIEMlessly Interactive Shell

A REPL-style interface for querying SIEM data in S3 with DuckDB.

Dot-commands:
    .profile [name]       Show or switch AWS profile
    .bucket  [name]       Show or set the active S3 bucket
    .sources              List registered data sources
    .schema  <source>     Show Parquet schema for a source
    .alerts  [options]    List recent alerts from CloudWatch
    .rules                List deployed detection rules
    .help                 Show command reference
    .quit / .exit         Exit the shell

Anything else is treated as a SQL query with automatic source-name
resolution (e.g. ``SELECT * FROM auth_logs WHERE ...``).
"""

import json
import os
import re
import sys
import shutil
import textwrap

import boto3
import duckdb
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter, merge_completers
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from pygments.lexers.sql import SqlLexer

# ── Colour palette ──────────────────────────────────────────────

PROMPT_STYLE = Style.from_dict(
    {
        "prompt": "#00d7af bold",
        "prompt.bracket": "#6c6c6c",
        "": "#d0d0d0",
    }
)

# ANSI helpers
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"


# ── Shell state ─────────────────────────────────────────────────


class ShellState:
    """Mutable state bag shared across all commands."""

    def __init__(self):
        self.profile: str | None = None
        self.bucket: str | None = None
        self.session: boto3.Session | None = None
        self.s3 = None
        self.logs = None
        self.sources: list[dict] = []
        self.source_map: dict[str, dict] = {}
        self.con: duckdb.DuckDBPyConnection | None = None
        self._duckdb_ready = False

    # ── AWS ──────────────────────────────────────────────────────

    def set_profile(self, profile: str):
        self.profile = profile
        self.session = boto3.Session(profile_name=profile)
        self.s3 = self.session.client("s3")
        self.logs = self.session.client("logs")
        # Reset DuckDB so it re-loads credentials
        self._duckdb_ready = False

    def set_bucket(self, bucket: str):
        self.bucket = bucket

    def ensure_s3(self):
        if not self.s3:
            raise ShellError("No AWS profile set. Run .profile first.")

    def ensure_bucket(self):
        self.ensure_s3()
        if not self.bucket:
            raise ShellError("No bucket set. Run .bucket <name> first.")

    # ── DuckDB ───────────────────────────────────────────────────

    def get_connection(self) -> duckdb.DuckDBPyConnection:
        if self.con is None:
            self.con = duckdb.connect(database=":memory:", read_only=False)
        if not self._duckdb_ready:
            self.con.execute("INSTALL httpfs;")
            self.con.execute("LOAD httpfs;")
            self.con.execute("INSTALL aws;")
            self.con.execute("LOAD aws;")
            if self.profile:
                self.con.execute(f"CALL load_aws_credentials('{self.profile}');")
            else:
                self.con.execute("CALL load_aws_credentials();")
            self._duckdb_ready = True
        return self.con

    # ── Sources ──────────────────────────────────────────────────

    def load_sources(self):
        self.ensure_bucket()
        resp = self.s3.get_object(
            Bucket=self.bucket, Key="sources/sources.json"
        )
        self.sources = json.loads(resp["Body"].read().decode("utf-8"))
        self.source_map = {s["name"]: s for s in self.sources}

    def resolve_query(self, query: str) -> str:
        """Replace bare source names after FROM/JOIN with S3 paths."""
        if not self.source_map:
            try:
                self.load_sources()
            except Exception:
                pass  # If sources aren't loaded, run raw query

        def _replace(match):
            prefix = match.group(1)
            name = match.group(2)
            if name in self.source_map:
                path = self.source_map[name]["parquet_path"].replace(
                    "{bucket}", self.bucket or ""
                )
                return f"{prefix}'{path}'"
            return match.group(0)

        return re.sub(
            r"((?:FROM|JOIN)\s+)(\w+)",
            _replace,
            query,
            flags=re.IGNORECASE,
        )


class ShellError(Exception):
    """User-facing errors that should be printed, not tracebacks."""


# ── Dot-commands ────────────────────────────────────────────────


def cmd_help(**_):
    """Show the command reference."""
    commands = [
        (".profile [name]", "Show or switch AWS profile"),
        (".bucket  [name]", "Show or set S3 bucket"),
        (".sources", "List data sources"),
        (".schema  <source>", "Show Parquet schema for a source"),
        (".alerts  [--severity S] [--days N]", "List recent alerts"),
        (".rules", "List deployed detection rules"),
        (".clear", "Clear the screen"),
        (".help", "This message"),
        (".quit / .exit", "Exit"),
        ("", ""),
        ("SELECT ...", "Run SQL (source names auto-resolve)"),
    ]
    print()
    for cmd, desc in commands:
        if cmd:
            print(f"  {GREEN}{cmd:<42}{RESET} {desc}")
        else:
            print()
    print()


def cmd_profile(state: ShellState, args: str):
    """Show or switch AWS profile."""
    available = boto3.Session().available_profiles

    if args.strip():
        name = args.strip()
        if name not in available:
            print(f"{RED}Profile '{name}' not found.{RESET} Available: {', '.join(available)}")
            return
        state.set_profile(name)
        print(f"{GREEN}✓{RESET} Profile set to {BOLD}{name}{RESET}")
        return

    # Interactive selection
    if not available:
        print(f"{YELLOW}No AWS profiles found in ~/.aws/credentials{RESET}")
        return

    print(f"\n  {BOLD}Available AWS profiles:{RESET}\n")
    for i, p in enumerate(available, 1):
        marker = f" {GREEN}← active{RESET}" if p == state.profile else ""
        print(f"    {DIM}{i}.{RESET} {p}{marker}")

    print(f"\n  {DIM}Usage: .profile <name>{RESET}\n")


def cmd_bucket(state: ShellState, args: str):
    """Show or set S3 bucket."""
    if args.strip():
        name = args.strip()
        state.set_bucket(name)
        # Try to load sources right away
        try:
            state.load_sources()
            n = len(state.sources)
            print(f"{GREEN}✓{RESET} Bucket set to {BOLD}{name}{RESET}  ({n} sources loaded)")
        except Exception as e:
            print(f"{GREEN}✓{RESET} Bucket set to {BOLD}{name}{RESET}")
            print(f"  {YELLOW}⚠ Could not load sources: {e}{RESET}")
        return

    if state.bucket:
        print(f"  Current bucket: {BOLD}{state.bucket}{RESET}")
    else:
        print(f"  {DIM}No bucket set. Usage: .bucket <name>{RESET}")


def cmd_sources(state: ShellState, **_):
    """List data sources."""
    state.ensure_bucket()
    if not state.sources:
        state.load_sources()

    if not state.sources:
        print(f"  {DIM}No sources found.{RESET}")
        return

    term_width = shutil.get_terminal_size().columns
    name_w = max(len(s["name"]) for s in state.sources) + 2

    print()
    print(f"  {BOLD}{'Source':<{name_w}} Description{RESET}")
    print(f"  {'─' * (min(term_width - 4, 70))}")
    for s in state.sources:
        desc = s.get("description", "")
        print(f"  {CYAN}{s['name']:<{name_w}}{RESET} {desc}")
    print()


def cmd_schema(state: ShellState, args: str):
    """Show Parquet schema for a source."""
    name = args.strip()
    if not name:
        print(f"  {DIM}Usage: .schema <source_name>{RESET}")
        return

    state.ensure_bucket()
    if not state.source_map:
        state.load_sources()

    if name in state.source_map:
        path = state.source_map[name]["parquet_path"].replace(
            "{bucket}", state.bucket
        )
    else:
        path = name  # Assume it's a raw S3 path

    con = state.get_connection()
    try:
        result = con.execute(f"DESCRIBE SELECT * FROM '{path}'").fetchdf()
        print()
        print(f"  {BOLD}Schema: {name}{RESET}")
        print(f"  {DIM}Path: {path}{RESET}")
        print()
        for _, row in result.iterrows():
            print(f"    {CYAN}{row['column_name']:<28}{RESET} {row['column_type']}")
        print()
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")


def cmd_alerts(state: ShellState, args: str):
    """List recent alerts from CloudWatch Logs."""
    state.ensure_bucket()
    if not state.logs:
        raise ShellError("No AWS profile set.")

    # Parse simple flags
    severity = None
    days = 7
    limit = 20
    tokens = args.split()
    i = 0
    while i < len(tokens):
        if tokens[i] == "--severity" and i + 1 < len(tokens):
            severity = tokens[i + 1]
            i += 2
        elif tokens[i] == "--days" and i + 1 < len(tokens):
            days = int(tokens[i + 1])
            i += 2
        elif tokens[i] == "--limit" and i + 1 < len(tokens):
            limit = int(tokens[i + 1])
            i += 2
        else:
            i += 1

    log_group = "/siemlessly/alerts"
    all_alerts = []

    try:
        streams = state.logs.describe_log_streams(
            logGroupName=log_group,
            logStreamNamePrefix="rule-",
            orderBy="LastEventTime",
            descending=True,
            limit=50,
        )
    except Exception as e:
        print(f"  {YELLOW}No alerts found: {e}{RESET}")
        return

    for stream in streams.get("logStreams", []):
        try:
            events = state.logs.get_log_events(
                logGroupName=log_group,
                logStreamName=stream["logStreamName"],
                limit=200,
            )
            for ev in events.get("events", []):
                alert = json.loads(ev["message"])
                all_alerts.append(alert)
        except Exception:
            continue

    if severity:
        all_alerts = [a for a in all_alerts if a.get("severity") == severity]

    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    all_alerts = all_alerts[:limit]

    if not all_alerts:
        print(f"  {DIM}No alerts found.{RESET}")
        return

    print()
    print(
        f"  {BOLD}{'Timestamp':<22} {'Rule':<32} {'Sev':<10} {'Matches'}{RESET}"
    )
    print(f"  {'─' * 72}")

    sev_colors = {"critical": RED, "high": YELLOW, "medium": CYAN, "low": DIM}
    for a in all_alerts:
        ts = str(a.get("timestamp", ""))[:19]
        sev = a.get("severity", "?")
        color = sev_colors.get(sev, "")
        print(
            f"  {ts:<22} {a.get('rule_name', '?'):<32} "
            f"{color}{sev:<10}{RESET} {a.get('matches_count', 0)}"
        )
    print()


def cmd_rules(state: ShellState, **_):
    """List deployed detection rules."""
    state.ensure_bucket()
    resp = state.s3.get_object(Bucket=state.bucket, Key="rules/rules.json")
    rules = json.loads(resp["Body"].read().decode("utf-8"))

    if not rules:
        print(f"  {DIM}No rules found.{RESET}")
        return

    sev_colors = {"critical": RED, "high": YELLOW, "medium": CYAN, "low": DIM}

    print()
    print(f"  {BOLD}{'ID':<30} {'Severity':<12} {'Enabled':<10} Name{RESET}")
    print(f"  {'─' * 78}")
    for r in rules:
        sev = r.get("severity", "?")
        color = sev_colors.get(sev, "")
        enabled = f"{GREEN}✓{RESET}" if r.get("enabled", True) else f"{RED}✗{RESET}"
        print(
            f"  {r['id']:<30} {color}{sev:<12}{RESET} {enabled:<10} {r['name']}"
        )
    print()


def cmd_clear(**_):
    """Clear the screen."""
    os.system("clear" if os.name != "nt" else "cls")


# ── SQL execution ───────────────────────────────────────────────


def run_sql(state: ShellState, query: str):
    """Execute a SQL query and print results as a formatted table."""
    state.ensure_bucket()
    con = state.get_connection()

    resolved = state.resolve_query(query)

    try:
        result = con.execute(resolved).fetchdf()
    except Exception as e:
        print(f"\n  {RED}Query error: {e}{RESET}\n")
        return

    n_rows = len(result)

    if n_rows == 0:
        print(f"\n  {DIM}0 rows returned.{RESET}\n")
        return

    # Print using DuckDB-style box formatting
    term_width = shutil.get_terminal_size().columns
    max_col_width = max(20, (term_width - 4) // max(len(result.columns), 1) - 3)

    # Truncate wide columns for display
    display = result.copy()
    for col in display.columns:
        display[col] = display[col].astype(str).str[:max_col_width]

    print()
    print(display.to_string(index=False, max_rows=100))
    print(f"\n  {DIM}{n_rows} row{'s' if n_rows != 1 else ''} returned.{RESET}\n")


# ── REPL ────────────────────────────────────────────────────────

DOT_COMMANDS = {
    ".help": cmd_help,
    ".profile": cmd_profile,
    ".bucket": cmd_bucket,
    ".sources": cmd_sources,
    ".schema": cmd_schema,
    ".alerts": cmd_alerts,
    ".rules": cmd_rules,
    ".clear": cmd_clear,
}

BANNER = f"""
{BOLD}{CYAN}  ┌─────────────────────────────────┐
  │        SIEMlessly Shell         │
  │    Serverless SIEM  ·  DuckDB   │
  └─────────────────────────────────┘{RESET}

  {DIM}Type .help for commands, or enter SQL directly.
  Source names (auth_logs, vpn_logs, ...) auto-resolve to S3.{RESET}
"""


def build_completer(state: ShellState) -> WordCompleter:
    """Build a tab-completer from dot-commands + source names + SQL keywords."""
    words = list(DOT_COMMANDS.keys()) + [".quit", ".exit"]

    # Source names
    words += [s["name"] for s in state.sources]

    # Common SQL keywords
    words += [
        "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "LIKE",
        "GROUP", "BY", "ORDER", "ASC", "DESC", "LIMIT", "OFFSET",
        "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "ON", "AS",
        "COUNT", "SUM", "AVG", "MIN", "MAX", "DISTINCT",
        "HAVING", "BETWEEN", "CASE", "WHEN", "THEN", "ELSE", "END",
        "CAST", "EXTRACT", "INTERVAL", "TIMESTAMP", "DATE",
        "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
        "WITH", "UNION", "ALL", "EXISTS", "IS", "NULL", "TRUE", "FALSE",
        "json_extract_string", "regexp_extract", "quantile_cont",
        "employee_id", "patient_id", "source_ip", "timestamp",
        "event_type", "event_id", "severity",
    ]

    return WordCompleter(words, ignore_case=True)


def main():
    print(BANNER)

    state = ShellState()

    # ── Step 1: AWS profile selection ────────────────────────────
    profiles = boto3.Session().available_profiles
    if profiles:
        print(f"  {BOLD}Available AWS profiles:{RESET}")
        for i, p in enumerate(profiles, 1):
            print(f"    {DIM}{i}.{RESET} {p}")

        print()
        try:
            while True:
                choice = input(f"  {GREEN}?{RESET} Select profile (name or number, Enter for 'default'): ").strip()
                if not choice:
                    choice = "default" if "default" in profiles else profiles[0]

                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(profiles):
                        choice = profiles[idx]
                    else:
                        print(f"  {RED}Invalid number.{RESET}")
                        continue

                if choice in profiles:
                    state.set_profile(choice)
                    print(f"  {GREEN}✓{RESET} Using profile: {BOLD}{choice}{RESET}\n")
                    break
                else:
                    print(f"  {RED}Profile '{choice}' not found.{RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            return
    else:
        print(f"  {YELLOW}No named profiles found, using default credentials.{RESET}")
        state.set_profile("default")

    # ── Step 2: Bucket selection ─────────────────────────────────
    print(f"  {DIM}Listing S3 buckets with 'siem' in name...{RESET}")
    try:
        all_buckets = state.s3.list_buckets().get("Buckets", [])
        siem_buckets = [b["Name"] for b in all_buckets if "siem" in b["Name"].lower()]

        if siem_buckets:
            print()
            for i, b in enumerate(siem_buckets, 1):
                print(f"    {DIM}{i}.{RESET} {b}")
            print()

            try:
                while True:
                    default_hint = f", Enter for {siem_buckets[0]}" if len(siem_buckets) == 1 else ""
                    choice = input(
                        f"  {GREEN}?{RESET} Select bucket (name or number{default_hint}): "
                    ).strip()
                    if not choice and len(siem_buckets) == 1:
                        choice = siem_buckets[0]
                    elif choice.isdigit():
                        idx = int(choice) - 1
                        if 0 <= idx < len(siem_buckets):
                            choice = siem_buckets[idx]
                        else:
                            print(f"  {RED}Invalid number.{RESET}")
                            continue

                    if choice:
                        state.set_bucket(choice)
                        break
                    print(f"  {RED}Please enter a bucket name or number.{RESET}")
            except (EOFError, KeyboardInterrupt):
                print(f"\n  {DIM}Goodbye.{RESET}\n")
                return
        else:
            bucket = input(f"  {GREEN}?{RESET} S3 bucket name: ").strip()
            state.set_bucket(bucket)
    except (EOFError, KeyboardInterrupt):
        print(f"\n  {DIM}Goodbye.{RESET}\n")
        return
    except Exception:
        try:
            bucket = input(f"  {GREEN}?{RESET} S3 bucket name: ").strip()
            state.set_bucket(bucket)
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            return

    # Load sources
    try:
        state.load_sources()
        print(
            f"  {GREEN}✓{RESET} Bucket: {BOLD}{state.bucket}{RESET}  "
            f"({len(state.sources)} sources loaded)\n"
        )
    except Exception as e:
        print(f"  {YELLOW}⚠ Could not load sources: {e}{RESET}\n")

    # ── Step 3: REPL ─────────────────────────────────────────────
    history_path = os.path.expanduser("~/.siemlessly_history")
    session = PromptSession(
        history=FileHistory(history_path),
        lexer=PygmentsLexer(SqlLexer),
        completer=build_completer(state),
        style=PROMPT_STYLE,
        multiline=False,
    )

    sql_buffer = []

    while True:
        try:
            prompt_text = [("class:prompt", "siemlessly"), ("class:prompt.bracket", "> ")]
            line = session.prompt(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            break

        if not line:
            continue

        # ── Quit ─────────────────────────────────────────────────
        if line.lower() in (".quit", ".exit", "quit", "exit"):
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            break

        # ── Dot-commands ─────────────────────────────────────────
        if line.startswith("."):
            parts = line.split(None, 1)
            cmd_name = parts[0].lower()
            cmd_args = parts[1] if len(parts) > 1 else ""

            handler = DOT_COMMANDS.get(cmd_name)
            if handler:
                try:
                    handler(state=state, args=cmd_args)
                    # Refresh completer after sources may have changed
                    session.completer = build_completer(state)
                except ShellError as e:
                    print(f"  {RED}{e}{RESET}")
                except TypeError:
                    # Some handlers don't take args
                    try:
                        handler()
                    except Exception as e:
                        print(f"  {RED}{e}{RESET}")
                except Exception as e:
                    print(f"  {RED}Error: {e}{RESET}")
            else:
                print(f"  {RED}Unknown command: {cmd_name}{RESET}  (type .help)")
            continue

        # ── Multi-line SQL (accumulate until semicolon) ──────────
        sql_buffer.append(line)

        # Check if the statement is complete (ends with ;)
        full = " ".join(sql_buffer)
        if not full.rstrip().endswith(";"):
            # Keep accumulating — switch to continuation prompt
            session.message = [("class:prompt", "     ... ")]
            continue

        # Reset prompt
        session.message = [("class:prompt", "siemlessly"), ("class:prompt.bracket", "> ")]

        # Strip trailing semicolon for DuckDB
        query = full.rstrip().rstrip(";")
        sql_buffer.clear()

        try:
            run_sql(state, query)
        except ShellError as e:
            print(f"  {RED}{e}{RESET}")
        except Exception as e:
            print(f"  {RED}Error: {e}{RESET}")


if __name__ == "__main__":
    main()
