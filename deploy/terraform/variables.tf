variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region to deploy into."
}

variable "stack_name" {
  type        = string
  default     = "idira-audit-securityhub"
  description = "Logical name used to namespace all created resources."
}

variable "artifacts_bucket" {
  type        = string
  description = "S3 bucket containing the Lambda deployment zip."
}

variable "artifacts_key" {
  type        = string
  default     = "idira-audit-securityhub.zip"
  description = "S3 key of the Lambda deployment zip."
}

variable "schedule_expression" {
  type        = string
  default     = "rate(1 hour)"
  description = "EventBridge schedule expression (e.g. 'rate(1 hour)', 'cron(0 * * * ? *)')."
}

variable "application_codes" {
  type        = string
  default     = ""
  description = "Comma-separated Idira application codes to filter. Empty = all."
}

variable "existing_secret_arn" {
  type        = string
  default     = ""
  description = "ARN of an existing Secrets Manager secret with Idira credentials. Leave empty to create one."
}
