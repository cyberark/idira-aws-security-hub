# Idira Audit → AWS Security Hub ETL

Scheduled AWS Lambda that pulls audit events from the **Idira Audit SIEM API** and imports them as ASFF findings into **AWS Security Hub**.

```
EventBridge (schedule)
  └─▶ Lambda (handler.py)
        ├─ Idira Audit SIEM API  (OAuth2 + stream pagination)
        │     └─ AuditDto[]
        ├─ Transform: AuditDto → OCSF → ASFF
        └─ AWS Security Hub  (BatchImportFindings)
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Idira Side – Service Account Setup](#idira-side--service-account-setup)
3. [AWS Side – Infrastructure Deployment](#aws-side--infrastructure-deployment)
   - [CloudFormation](#option-a-cloudformation-one-command)
   - [Terraform](#option-b-terraform)
4. [Secrets Manager – Filling in Credentials](#secrets-manager--filling-in-credentials)
5. [Configuration Reference](#configuration-reference)
6. [Local Development](#local-development)
7. [Running Tests](#running-tests)
8. [Operations](#operations)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python ≥ 3.12 | Lambda runtime; also used for local dev |
| AWS CLI v2 | Authenticated with sufficient permissions |
| AWS Security Hub | Must be **enabled** in the target region before deployment |
| S3 bucket (same region) | Holds the Lambda deployment zip |
| Idira tenant | Admin access to create a service account |

---

## Idira Side – Service Account Setup

You need an OAuth2 service account with read access to the Audit API. The required credentials end up as six fields in AWS Secrets Manager (see [next section](#secrets-manager--filling-in-credentials)).

### 1. Create a service account / OAuth2 app

1. Log in to your Idira Identity portal (`https://<tenant>.id.cyberark.cloud`).
2. Navigate to **Settings → Users** (or **Apps → OAuth2 Client**) and create a **confidential client** (service account).
3. Grant it the scope: `isp.audit.events:read`.
4. Note the **Client ID** and **Client Secret** that are generated.

### 2. Locate the Web App name

The OAuth2 token endpoint is:
```
POST https://<tenant>.id.cyberark.cloud/oauth2/token/<web_app>
```
`<web_app>` is the name of the OAuth2 application configured in the Identity portal.

### 3. Obtain the API key

The Audit SIEM API requires an additional `x-api-key` header.  
Generate or retrieve the API key from **Audit → Integrations → SIEM** in the Idira Admin console.

### 4. Collect all six values

| Field | Description | Example                              |
|---|---|--------------------------------------|
| `api_base_url` | Idira Audit API base URL | `https://<tenant>.cyberark.cloud`    |
| `identity_url` | Idira Identity (OAuth2) URL | `https://<tenant>.id.cyberark.cloud` |
| `client_id` | OAuth2 client ID | `audit-reader@tenant`                |
| `client_secret` | OAuth2 client secret | *(keep secret)*                      |
| `web_app` | OAuth2 web app name | `my-web-app`                         |
| `api_key` | SIEM API key | *(keep secret)*                      |

---

## AWS Side – Infrastructure Deployment

Both **CloudFormation** and **Terraform** options create identical resources:

| Resource | Name pattern |
|---|---|
| Lambda function | `idira-audit-securityhub-<stack>` |
| IAM execution role | `idira-audit-lambda-role-<stack>` |
| EventBridge rule | `idira-audit-schedule-<stack>` |
| SSM Parameter (cursor) | `/idira-audit/<stack>/cursor` |
| Secrets Manager secret | `/idira-audit/<stack>/credentials` |

### Option A: CloudFormation (one command)

The `deploy/build.sh` script packages the Lambda, uploads it to S3, and deploys the stack in one shot.

```bash
# Minimal – uses all defaults (us-east-1, hourly schedule)
./deploy/build.sh my-artifacts-bucket

# Custom stack name + region
./deploy/build.sh my-artifacts-bucket idira-audit-prod us-east-1

# With a named AWS profile
./deploy/build.sh my-artifacts-bucket idira-audit-prod us-east-1 my-aws-profile
```

**What the script does:**
1. `pip install` runtime dependencies into a temp build directory.
2. Packages `lambda/` (excluding tests, `.env`, generated JSON/CSV) into `deploy/idira-audit-securityhub.zip`.
3. Uploads the zip to the S3 bucket.
4. Runs `aws cloudformation deploy` with `CAPABILITY_NAMED_IAM`.
5. Prints stack outputs.

**CloudFormation parameters** (pass with `--parameter-overrides` if using the AWS CLI directly):

| Parameter | Default | Description |
|---|---|---|
| `ArtifactsBucket` | *(required)* | S3 bucket for the Lambda zip |
| `ArtifactsKey` | `idira-audit-securityhub.zip` | S3 key of the zip |
| `ScheduleExpression` | `rate(1 hour)` | EventBridge schedule (e.g. `rate(30 minutes)`) |
| `ApplicationCodes` | *(empty = all)* | Comma-separated Idira app codes to filter (e.g. `PAM,EPM`) |
| `ExistingSecretArn` | *(empty = create new)* | ARN of a pre-existing Secrets Manager secret |

---

### Option B: Terraform

```bash
cd deploy/terraform

# First time
terraform init

# Review
terraform plan -var="artifacts_bucket=my-artifacts-bucket"

# Apply
terraform apply -var="artifacts_bucket=my-artifacts-bucket"
```

**Key variables** (`deploy/terraform/variables.tf`):

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | Target AWS region |
| `stack_name` | `idira-audit-securityhub` | Resource name suffix |
| `artifacts_bucket` | *(required)* | S3 bucket for the Lambda zip |
| `artifacts_key` | `idira-audit-securityhub.zip` | S3 key of the zip |
| `schedule_expression` | `rate(1 hour)` | EventBridge schedule |
| `application_codes` | *(empty = all)* | Comma-separated app code filter |
| `existing_secret_arn` | *(empty = create new)* | Bring-your-own secret |

> **Note:** Upload the Lambda zip to S3 before running `terraform apply`, or run `deploy/build.sh` first (it handles the upload).

---

## Secrets Manager – Filling in Credentials

Both deployment methods create a placeholder secret at `/idira-audit/<stack>/credentials`. You must populate it with real values before invoking the Lambda.

```bash
# Retrieve the secret ARN from the stack outputs
SECRET_ARN=$(aws cloudformation describe-stacks \
  --stack-name idira-audit-securityhub \
  --query 'Stacks[0].Outputs[?OutputKey==`SecretArn`].OutputValue' \
  --output text)

# Update the secret with your Idira credentials
aws secretsmanager put-secret-value \
  --secret-id "$SECRET_ARN" \
  --secret-string '{
    "api_base_url":  "https://<tenant>.cyberark.cloud",
    "identity_url":  "https://<tenant>.id.cyberark.cloud",
    "client_id":     "your-client-id",
    "client_secret": "your-client-secret",
    "web_app":       "your-web-app-name",
    "api_key":       "your-api-key"
  }'
```

---

## Configuration Reference

### Lambda environment variables

Set in the CloudFormation/Terraform template. Modify in the console or redeploy to change.

| Variable | Required | Description |
|---|---|---|
| `IDIRA_SECRET_ARN` | ✅ | ARN of the Secrets Manager secret with Idira credentials |
| `CURSOR_SSM_PARAM` | ✅ | SSM Parameter name storing the pagination cursor (auto-set by template) |
| `AWS_ACCOUNT_ID` | ✅ | 12-digit AWS account ID (auto-set by template) |
| `APPLICATION_CODES` | ❌ | Comma-separated Idira app codes to filter, e.g. `PAM,EPM`. Omit to fetch all |
| `FETCH_EVENTS_DAYS` | ❌ | If > 0, fetch events starting N days ago instead of from the cursor |

### Local `.env` variables (local dev only)

| Variable | Description |
|---|---|
| `LOCAL_EXECUTION` | Set to `true` to activate local mode (skips SSM/Secrets Manager) |
| `IDIRA_API_BASE_URL` | Idira Audit API base URL |
| `IDIRA_IDENTITY_URL` | Idira Identity (OAuth2) URL |
| `IDIRA_CLIENT_ID` | OAuth2 client ID |
| `IDIRA_CLIENT_SECRET` | OAuth2 client secret |
| `IDIRA_WEB_APP` | OAuth2 web app name |
| `IDIRA_API_KEY` | SIEM API key |
| `AWS_ACCOUNT_ID` | 12-digit AWS account ID |
| `AWS_REGION` | AWS region (default: `us-east-1`) |
| `AWS_PROFILE` | Named AWS CLI profile to use for Security Hub publishing |
| `APPLICATION_CODES` | Optional comma-separated app code filter |
| `FETCH_EVENTS_DAYS` | Optional lookback window in days |
| `EVENT_SOURCE` | `api` (default) or `csv` (load from a downloaded CSV report) |
| `CSV_REPORT_PATH` | Path to the CSV file when `EVENT_SOURCE=csv` (default: `c3_events_report.csv`) |

---

## Local Development

### Setup

```bash
# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# Install all dependencies (runtime + dev)
pip install -r requirements-dev.txt
```

### `.env` file

Create `lambda/.env` (gitignored) with your local credentials:

```dotenv
LOCAL_EXECUTION=true

IDIRA_API_BASE_URL=https://<tenant>.cyberark.cloud
IDIRA_IDENTITY_URL=https://<tenant>.id.cyberark.cloud
IDIRA_CLIENT_ID=your-client-id
IDIRA_CLIENT_SECRET=your-client-secret
IDIRA_WEB_APP=your-web-app-name
IDIRA_API_KEY=your-api-key

AWS_ACCOUNT_ID=123456789012
AWS_REGION=us-east-1
AWS_PROFILE=your-aws-profile

# Optional: limit to specific services
# APPLICATION_CODES=PAM,EPM

# Optional: fetch the last N days instead of using the cursor
# FETCH_EVENTS_DAYS=7
```

### Run the ETL locally

```bash
cd lambda
python main.py
```

Output files written to `lambda/`:
- `events.json` — raw AuditDto events from the API
- `ocsf_events.json` — transformed OCSF events
- `asff_findings.json` — ASFF findings submitted to Security Hub

### Run from a downloaded CSV report

Set `EVENT_SOURCE=csv` (and optionally `CSV_REPORT_PATH`) in your `.env` to process a CSV exported from the Idira Audit portal instead of calling the API:

```dotenv
EVENT_SOURCE=csv
CSV_REPORT_PATH=/path/to/your/report.csv
```

---

## Running Tests

```bash
cd lambda
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## Operations

### Cursor management

The Lambda tracks its position using a **cursor** stored in SSM Parameter Store at `/idira-audit/<stack>/cursor`. After each successful run the cursor is updated automatically.

**Reset the cursor** (re-process from a specific date):

```bash
aws ssm put-parameter \
  --name "/idira-audit/<stack>/cursor" \
  --value "UNSET" \
  --type String \
  --overwrite
```

Setting the value to `UNSET` causes the next run to use `FETCH_EVENTS_DAYS` (if set) or the current timestamp as the start.

**Force a historical backfill** (one-off):

Set the `FETCH_EVENTS_DAYS` Lambda environment variable to the desired lookback window, invoke the function, then remove the variable to resume cursor-based operation.

### Manual invocation

```bash
aws lambda invoke \
  --function-name idira-audit-securityhub-<stack> \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  response.json && cat response.json
```

### Viewing findings in Security Hub

In the AWS console, go to **Security Hub → Findings** and filter by:
- **Product name**: `Idira Audit`
- **Company name**: `Idira`
- **Generator ID prefix**: `IdiraAudit/`
