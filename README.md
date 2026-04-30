# siemlessly

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

### Prerequisites

- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- Python 3.12+
- AWS credentials configured (`aws configure` or environment variables)

### IAM permissions

The deploying identity (your local IAM user/role, or the GitHub OIDC role) needs
permissions to create and manage the resources in the SAM template. A scoped
policy looks like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudFormation",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "cloudformation:CreateChangeSet",
        "cloudformation:DescribeChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteChangeSet"
      ],
      "Resource": "arn:aws:cloudformation:*:*:stack/siemlessly/*"
    },
    {
      "Sid": "CloudFormationTransform",
      "Effect": "Allow",
      "Action": "cloudformation:ValidateTemplate",
      "Resource": "*"
    },
    {
      "Sid": "S3SAMArtifacts",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:aws:s3:::aws-sam-cli-managed-default-*"
    },
    {
      "Sid": "S3SiemBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutLifecycleConfiguration",
        "s3:PutBucketNotification",
        "s3:GetBucketNotification"
      ],
      "Resource": "arn:aws:s3:::siem-data-*"
    },
    {
      "Sid": "IAM",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PassRole",
        "iam:TagRole"
      ],
      "Resource": "arn:aws:iam::*:role/siemlessly-*"
    },
    {
      "Sid": "Lambda",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:TagResource"
      ],
      "Resource": "arn:aws:lambda:*:*:function:siemlessly-*"
    },
    {
      "Sid": "ECS",
      "Effect": "Allow",
      "Action": [
        "ecs:CreateCluster",
        "ecs:DeleteCluster",
        "ecs:RegisterTaskDefinition",
        "ecs:DeregisterTaskDefinition",
        "ecs:DescribeClusters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SNS",
      "Effect": "Allow",
      "Action": [
        "sns:CreateTopic",
        "sns:DeleteTopic",
        "sns:GetTopicAttributes",
        "sns:SetTopicAttributes",
        "sns:TagResource"
      ],
      "Resource": "arn:aws:sns:*:*:siem-alerts-*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutRetentionPolicy",
        "logs:DescribeLogGroups",
        "logs:TagResource"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/siemlessly/*"
    },
    {
      "Sid": "EventBridge",
      "Effect": "Allow",
      "Action": [
        "events:PutRule",
        "events:DeleteRule",
        "events:PutTargets",
        "events:RemoveTargets",
        "events:DescribeRule"
      ],
      "Resource": "arn:aws:events:*:*:rule/HourlySiemDetections"
    }
  ]
}
```

> **Note:** For a first deploy you can use `AdministratorAccess` and then scope
> down to the policy above once the stack is stable.

### Deploy (local)

First deploy — interactive, saves answers to `samconfig.toml`:

```bash
sam build --template-file infra/template.yaml
sam deploy --guided
```

Subsequent deploys:

```bash
sam build --template-file infra/template.yaml
sam deploy
```

### Deploy (CI/CD)

Pushes to `main` that touch `infra/` trigger the `deploy-infra` GitHub Actions
workflow automatically. You can also trigger it manually from the Actions tab.

Required GitHub repo secrets:

| Secret | Description |
|---|---|
| `AWS_ROLE_ARN` | IAM role ARN for GitHub OIDC federation |
| `AWS_REGION` | Target region (e.g. `us-west-2`) |

To set up GitHub OIDC with AWS:

1. In IAM → Identity providers, add an OpenID Connect provider for
   `token.actions.githubusercontent.com` (audience: `sts.amazonaws.com`)
2. Create an IAM role that trusts the OIDC provider, scoped to your repo:
   ```json
   {
     "Effect": "Allow",
     "Principal": {
       "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
     },
     "Action": "sts:AssumeRoleWithWebIdentity",
     "Condition": {
       "StringEquals": {
         "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
       },
       "StringLike": {
         "token.actions.githubusercontent.com:sub": "repo:<GITHUB_ORG>/<REPO_NAME>:*"
       }
     }
   }
   ```
3. Attach the deploy policy (above) to the role
4. Set the role ARN as the `AWS_ROLE_ARN` secret

### Configuration

Files in `config/` are uploaded to S3 by the `deploy-config` workflow (triggered
on pushes to `main` that touch `config/`).

**`config/sources/sources.json`** — data source definitions. Maps names to S3 paths:

```json
[
  {
    "name": "web_logs",
    "parquet_path": "s3://{bucket}/processed/*/*.parquet",
    "raw_path": "s3://{bucket}/raw/http-logs/"
  }
]
```

**`config/rules/rules.json`** — detection rules:

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

Rules use source names from `sources.json` as table names in their SQL queries
(e.g. `FROM web_logs`). CloudWatch Logs is always written to. `destinations` is
optional per rule.

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

- **On new data** — triggered by S3 `ObjectCreated` events on `processed/*.parquet`
- **Scheduled** — runs every hour against all processed data

Each rule's query uses DuckDB to query Parquet files directly from S3. Use
`{bucket}` as a placeholder for the bucket name in source definitions.
