terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.name
  create_secret = var.existing_secret_arn == ""
  secret_arn    = local.create_secret ? aws_secretsmanager_secret.idira[0].arn : var.existing_secret_arn
}

# ── Secrets Manager ──────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "idira" {
  count       = local.create_secret ? 1 : 0
  name        = "/idira-audit/${var.stack_name}/credentials"
  description = "Idira Audit API credentials for the Security Hub ETL."
}

resource "aws_secretsmanager_secret_version" "idira" {
  count     = local.create_secret ? 1 : 0
  secret_id = aws_secretsmanager_secret.idira[0].id
  secret_string = jsonencode({
    api_base_url  = "https://REPLACE_ME.cyberark.cloud"
    identity_url  = "https://REPLACE_ME.id.cyberark.cloud"
    client_id     = "REPLACE_ME"
    client_secret = "REPLACE_ME"
    web_app       = "REPLACE_ME"
    api_key       = "REPLACE_ME"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ── SSM Parameter (run cursor) ───────────────────────────────────────────────

resource "aws_ssm_parameter" "cursor" {
  name        = "/idira-audit/${var.stack_name}/cursor"
  type        = "String"
  value       = "UNSET"
  description = "Last-run timestamp cursor for the Idira Audit ETL."

  lifecycle {
    ignore_changes = [value]
  }
}

# ── IAM Role ─────────────────────────────────────────────────────────────────

resource "aws_iam_role" "lambda" {
  name = "idira-audit-lambda-role-${var.stack_name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "etl_policy" {
  name = "IdiraAuditETLPolicy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SecurityHubImportV2"
        Effect   = "Allow"
        Action   = "securityhub:BatchImportFindingsV2"
        Resource = "*"
      },
      {
        Sid    = "SSMCursor"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/idira-audit/${var.stack_name}/cursor"
      },
      {
        Sid      = "SecretsManagerRead"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = local.secret_arn
      }
    ]
  })
}

# ── Lambda Function ──────────────────────────────────────────────────────────

resource "aws_lambda_function" "etl" {
  function_name = "idira-audit-securityhub-${var.stack_name}"
  description   = "Fetches Idira audit events and imports them into AWS Security Hub."
  handler       = "handler.handler"
  runtime       = "python3.12"
  role          = aws_iam_role.lambda.arn
  timeout       = 300
  memory_size   = 256

  s3_bucket = var.artifacts_bucket
  s3_key    = var.artifacts_key

  environment {
    variables = {
      PYTHONPATH        = "/var/task"
      AWS_DATA_PATH     = "/var/task/botocore/data"
      IDIRA_SECRET_ARN  = local.secret_arn
      CURSOR_SSM_PARAM  = aws_ssm_parameter.cursor.name
      AWS_ACCOUNT_ID    = local.account_id
      APPLICATION_CODES = var.application_codes
    }
  }

  depends_on = [aws_iam_role_policy_attachment.basic_execution]
}

# ── EventBridge Schedule ─────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "idira-audit-schedule-${var.stack_name}"
  description         = "Triggers the Idira Audit → Security Hub ETL Lambda."
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "etl" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  arn       = aws_lambda_function.etl.arn
  target_id = "IdiraAuditETLTarget"
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.etl.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
