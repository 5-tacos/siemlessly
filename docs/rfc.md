# RFC: SIEMlessly Architecture

> **Status**: Implemented  
> **Author**: Team Siemlessly  
> **Date**: 2026-05-01  

---

## 1. Problem Statement

Healthcare organizations generate millions of log events per day across web servers, databases, authentication systems, VPN gateways, EHR platforms, CloudTrail, and network flow monitors. A security operations team needs to:

1. **Ingest** raw logs of varying formats and volumes into a queryable store.
2. **Detect** threats automatically — both in near-real-time (on new data arrival) and periodically (scheduled sweeps).
3. **Investigate** alerts interactively with ad-hoc SQL, joining across all log types.
4. **Alert** to CloudWatch, SNS, and external webhooks.

Traditional SIEMs (Splunk, Elastic SIEM) are expensive at healthcare-scale ingestion rates and require dedicated infrastructure. We need a serverless-first architecture that is cost-efficient at rest, scales on demand, and can be deployed with `sam deploy`.

---

## 2. Architecture Overview

```
                      ┌──────────────┐
                      │  Raw logs    │
                      │  (.jsonl.gz) │
                      └──────┬───────┘
                             │ S3 PutObject
                             ▼
                   ┌─────────────────────┐
                   │   EventBridge Rule   │
                   │  (prefix: raw/)      │
                   └─────────┬───────────┘
                             │ Triggers
                             ▼
                   ┌─────────────────────┐
                   │  Fargate Task        │
                   │  (extract_to_parquet)│
                   │  4 vCPU / 16 GB     │
                   └─────────┬───────────┘
                             │ Writes partitioned Parquet
                             ▼
            ┌────────────────────────────────────┐
            │   S3: processed/<type>/dt=YYYY-MM-DD/ │
            │   (Snappy-compressed Parquet)          │
            └───────────┬───────────────┬────────┘
                        │               │
           S3 ObjectCreated       EventBridge (hourly)
                        │               │
                        ▼               ▼
               ┌────────────────────────────┐
               │  Detection Engine Lambda    │
               │  DuckDB in-memory           │
               │  6 GB / 10 min timeout      │
               └──────┬──────────┬──────────┘
                      │          │
                      ▼          ▼
            CloudWatch Logs    SNS / Webhook
            (/siemlessly/      (per-rule
             alerts)            destinations)

               ┌────────────────────────────┐
               │  Query Engine Lambda        │
               │  Ad-hoc SQL via CLI         │
               │  4 GB / 5 min timeout       │
               └────────────────────────────┘
```

### Component Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Storage** | S3 + Parquet (Snappy) | Durable, columnar, cost-efficient log store |
| **Ingestion** | Fargate (ECS) | Streaming JSON → Parquet conversion with date partitioning |
| **Detection** | Lambda + DuckDB | Runs 10 SQL rules against Parquet on S3 |
| **Query** | Lambda + DuckDB | Ad-hoc analyst queries |
| **Alerting** | CloudWatch Logs + SNS | Alert persistence and notification |
| **CI/CD** | GitHub Actions + SAM | Infra-as-code deploys on push to `main` |
| **CLI** | Python (Typer) | Local analyst interface |

---

## 3. Design Decisions & Tradeoffs

### 3.1 Why Parquet over raw JSON?

| Factor | Raw JSON (gzipped) | Parquet (Snappy) |
|--------|-------------------|------------------|
| Query speed | Full scan required | Columnar pruning — only reads queried columns |
| Compression | ~10:1 | ~15:1 (columnar compresses better) |
| Schema enforcement | None | Enforced at write time |
| DuckDB integration | Possible but slow | Native, zero-copy reads |
| Partition support | Manual | Built into path structure (`dt=YYYY-MM-DD`) |

**Decision**: Convert to Parquet at ingestion time. The ingestion Fargate task pays the conversion cost once; every subsequent query benefits.

**Tradeoff**: Ingestion latency increases by ~30–60 seconds for Parquet conversion. Acceptable for a SIEM where detection SLA is minutes, not milliseconds.

### 3.2 Why DuckDB over Athena?

| Factor | Athena | DuckDB (Lambda) |
|--------|--------|-----------------|
| Cold start | ~2–5 seconds (query planning) | ~1 second (extension load) |
| Cost | $5/TB scanned | $0 (Lambda compute only) |
| Concurrency | 20 concurrent queries default | One per Lambda invocation |
| Joins | Full SQL | Full SQL |
| S3 integration | Native | Via `httpfs` + `aws` extensions |
| Operational overhead | Workgroup config, result buckets | None — ephemeral in-memory |

**Decision**: DuckDB in Lambda. At our data scale (< 10 GB processed Parquet), DuckDB reads directly from S3 faster and cheaper than Athena. Lambda's pay-per-invocation model means zero cost at rest.

**Tradeoff**: DuckDB in Lambda has a 10 GB memory ceiling and 15-minute timeout. For datasets > ~50 GB, Athena or a Fargate-based DuckDB process would be necessary. This is a known scaling limit we accept for the current dataset size.

### 3.3 Why Fargate for Ingestion (not Lambda)?

| Factor | Lambda | Fargate |
|--------|--------|---------|
| Timeout | 15 minutes | Unlimited |
| Memory | 10 GB max | 30 GB (on 4 vCPU) |
| Disk | 10 GB `/tmp` | 200 GB ephemeral |
| Streaming I/O | Awkward (S3 GetObject + buffering) | Native (stream from S3 Body) |
| Cost per invocation | Cheap for short tasks | Higher baseline, but amortized over long runs |

**Decision**: Fargate with 4 vCPU / 16 GB. Raw log files can be multi-GB gzipped archives. Fargate gives us streaming decompression, PyArrow's columnar writer, and no timeout pressure.

**Tradeoff**: Fargate cold start is ~30–60 seconds (image pull). Mitigated by using a slim Python image and pre-installing only `boto3` + `pyarrow`.

### 3.4 Why Date Partitioning?

Partitioning by `dt=YYYY-MM-DD` means detection rules with `WHERE timestamp >= (now() - INTERVAL 7 DAY)` only scan ~7 partition directories instead of the full 91-day corpus. DuckDB's glob-based file discovery naturally prunes partitions that don't match the date filter.

**Decision**: Partition by date per event type: `processed/{event_type}/dt={date}/chunk_{n}.parquet`.

**Tradeoff**: Cross-type joins (e.g., auth_logs JOIN vpn_logs) require scanning two partition trees. Acceptable because these joins are scoped to specific employees and short time windows.

### 3.5 Why Two Triggers for Detection?

The detection engine fires on:

1. **S3 ObjectCreated** (near-real-time): When a new Parquet chunk lands in `processed/`, the Lambda runs all rules against _only that file_. Low latency but limited to one file's worth of data.

2. **EventBridge Schedule** (hourly): The Lambda runs all rules against _all_ partitioned data using the full glob paths from `sources.json`. This catches patterns that span multiple files or require lookback windows.

**Decision**: Dual-trigger architecture. Event-driven for speed, scheduled for completeness.

**Tradeoff**: Some rules may fire twice for the same event — once in event-driven mode and again in the scheduled sweep. This is acceptable because alerts are idempotent (written to CloudWatch with the same rule ID and date, so duplicates are visible but not actionable).

### 3.6 Why `cloudwatch` as a Destination Type?

CloudWatch Logs is _always_ written for every alert (via `write_alert_to_cloudwatch()`). Listing `"type": "cloudwatch"` in a rule's `destinations` array is purely declarative — it documents intent without duplicating writes. This was a conscious design choice:

- Rules should be self-describing. A reader of `rules.json` should know where alerts go without reading Python code.
- The engine explicitly handles `cloudwatch` as a no-op in `forward_to_destinations()`.

---

## 4. Data Flow: End to End

### 4.1 Ingestion

```
1. Analyst/pipeline uploads raw logs to s3://<bucket>/raw/<file>.jsonl.gz
2. S3 emits ObjectCreated event → EventBridge
3. EventBridge rule matches prefix "raw/" → runs Fargate task
4. Fargate container:
   a. Streams the file from S3 (gzip decompression)
   b. Classifies each JSON line into one of 7 event types
   c. Normalizes nested objects to JSON strings
   d. Buffers rows per (event_type, date)
   e. Flushes 100K-row chunks as Snappy Parquet to:
      s3://<bucket>/processed/<event_type>/dt=<date>/chunk_<n>.parquet
```

### 4.2 Detection

```
1. New Parquet file lands → S3 ObjectCreated → Detection Lambda
2. Lambda loads rules from s3://<bucket>/rules/rules.json (cached 5 min)
3. Lambda loads sources from s3://<bucket>/sources/sources.json (cached 10 min)
4. For each enabled rule:
   a. Resolve source names in SQL to S3 paths (event-driven: specific file; scheduled: glob)
   b. Execute SQL via DuckDB → S3 Parquet reads
   c. If matches > 0: write alert to CloudWatch + forward to rule destinations
```

### 4.3 Investigation

```
1. Analyst runs: siemlessly query run "SELECT * FROM auth_logs WHERE employee_id = 'EMP-003'"
2. CLI resolves "auth_logs" → s3://<bucket>/processed/auth_logs/dt=*/*.parquet
3. DuckDB reads Parquet from S3, executes query, returns results
```

---

## 5. Event Type Classification

The ingestion pipeline classifies raw JSON events into 7 types using discriminating field checks:

| Event Type | Key Fields | Volume (typical) |
|------------|-----------|------------------|
| `vpn_logs` | `vpn_endpoint`, event_id prefix `vpn-` | Low |
| `ehr_access` | `patient_id`, event_id prefix `ehr-` | Medium |
| `auth_logs` | `auth_method`, event_id prefix `auth-` | Medium |
| `http_logs` | `http_method` | High |
| `db_queries` | `query_type` | High |
| `cloudtrail` | `event_source` | Medium |
| `network_flows` | `destination_ip` | High |

Classification is ordered most-specific-first to avoid misclassification (e.g., a CloudTrail event with `event_source` could be mistaken for other types if checked last).

---

## 6. Security Posture

### 6.1 IAM Least Privilege

Each component has a scoped IAM role:

| Role | Permissions |
|------|------------|
| `SiemIngestionTaskRole` | `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` on the SIEM bucket only |
| `QueryEngineRole` | `s3:GetObject`, `s3:ListBucket` (read-only) |
| `DetectionEngineRole` | S3 read + `sns:Publish` + CloudWatch Logs write |
| `SiemIngestionTaskExecutionRole` | ECS task execution + CloudWatch Logs for container stdout |

### 6.2 Data at Rest

- S3 default encryption (SSE-S3) applies to all objects.
- Lifecycle rule transitions `processed/` data to STANDARD_IA after 30 days for cost optimization.

### 6.3 Network

- Fargate tasks run in customer-specified subnets with a customer-specified security group.
- Lambda functions run in the default VPC-less configuration with IAM-based S3 access.

---

## 7. CI/CD

Two GitHub Actions workflows:

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `deploy-infra.yml` | Push to `main` touching `infra/` | `sam build` + `sam deploy` |
| `deploy-config.yml` | Push to `main` touching `config/` | `aws s3 cp` rules + sources to S3 |

Both use GitHub OIDC federation — no long-lived AWS credentials in GitHub Secrets.

---

## 8. Known Limitations & Future Work

| Limitation | Impact | Mitigation / Future |
|------------|--------|-------------------|
| DuckDB memory ceiling (10 GB Lambda) | Cannot scan datasets > ~50 GB in one invocation | Move to Fargate-based DuckDB for large sweeps |
| No deduplication on dual-trigger alerts | Same event may appear in two CloudWatch entries | Add alert dedup key (rule_id + match hash) |
| Webhook uses `urllib` (no retry/backoff) | Transient failures lose alerts | Add SQS dead-letter queue for failed deliveries |
| No RBAC on CLI | Any AWS credential holder can query all data | Add IAM-based access controls per source |
| Classifier is heuristic-based | Unknown event types go to `unknown` bucket | Add schema validation / reject unknown events |
| No data retention policy on raw logs | Raw logs accumulate indefinitely | Add S3 lifecycle rule for `raw/` prefix |

---

## 9. Cost Estimate (Steady State)

Assuming 1 million events/day, 91-day retention:

| Component | Monthly Cost |
|-----------|-------------|
| S3 (Standard, ~5 GB Parquet) | ~$0.12 |
| S3 (Standard-IA after 30 days) | ~$0.05 |
| Fargate (4 vCPU, 16 GB, ~5 min/day) | ~$3.00 |
| Lambda — Detection (6 GB, 10 runs/day × 30s) | ~$0.60 |
| Lambda — Query (4 GB, ~50 ad-hoc/day × 5s) | ~$0.15 |
| CloudWatch Logs (alerts) | ~$0.50 |
| EventBridge | ~$0.01 |
| **Total** | **~$4.43/month** |

This is roughly **100× cheaper** than a managed SIEM at equivalent ingest volume.
