# siemlessly

opencode -s ses_228adec73ffex4dsuhV05yWTiX


Serverless SIEM on AWS. Ingests raw logs, converts to Parquet, runs detection rules against the data.

## Architecture

```
raw logs (S3) --> Fargate (parquet conversion) --> S3 processed/
                                                      |
                                          Detection Lambda (DuckDB)
                                          |              |
                                          v              v
                                  CloudWatch Logs    SNS / webhook
```

## Directory structure

```
infra/     SAM template, Lambda code, Fargate Dockerfile
config/    Rules, source definitions (deployed to S3)
cli/       CLI tool for querying logs and viewing alerts
```

## Setup

### Infrastructure

Deploy with GitHub Actions (push to `main`) or manually:

```bash
sam deploy --template-file infra/template.yaml --stack-name siemlessly --resolve-s3
```

Required secrets in GitHub repo:

| Secret | Description |
|---|---|
| `AWS_ROLE_ARN` | IAM role for OIDC |
| `AWS_REGION` | Target region |
| `SAM_S3_BUCKET` | Bucket for SAM staging artifacts |
| `SIEM_DATA_BUCKET` | SIEM data bucket name |

### Configuration

Files in `config/` are uploaded to S3 by the `deploy-config` workflow.

**`config/sources/sources.json`** - data source definitions. Maps names to S3 paths:

```json
[
  {
    "name": "web_logs",
    "parquet_path": "s3://{bucket}/processed/*/*.parquet",
    "raw_path": "s3://{bucket}/raw/http-logs/"
  }
]
```

**`config/rules/rules.json`** - detection rules:

```json
[
  {
    "id": "high-500-errors",
    "name": "High Volume of 500 Errors",
    "query": "SELECT count(*) as err_count, source_ip FROM web_logs WHERE status_code >= 500 GROUP BY source_ip HAVING err_count > 50",
    "severity": "high",
    "enabled": true,
    "destinations": [
      { "type": "sns", "config": { "topic_arn": "arn:aws:sns:..." } }
    ]
  }
]
```

Rules use source names from `sources.json` in their queries. CloudWatch Logs is always written to. `destinations` is optional per rule.

## CLI

```bash
# Query logs by source name
siemlessly query run "SELECT * FROM web_logs WHERE status_code = 500"

# Query by raw S3 path
siemlessly query run "SELECT * FROM 's3://bucket/processed/...'"

# View schema
siemlessly query schema "s3://bucket/processed/.../*.parquet"

# List sources
siemlessly sources list

# View alerts from CloudWatch
siemlessly alerts list --severity critical --days 7
siemlessly alerts get <rule-id>
```

## Detection rules

Rules are evaluated:

- **On new data** - triggered by S3 `ObjectCreated` events on `processed/*.parquet`
- **Scheduled** - runs every hour against all processed data

Each rule's query uses DuckDB to query Parquet files directly from S3. Use `{bucket}` as a placeholder for the bucket name in source definitions.
