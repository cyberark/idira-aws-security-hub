output "lambda_function_name" {
  description = "Name of the deployed Lambda function."
  value       = aws_lambda_function.etl.function_name
}

output "lambda_function_arn" {
  description = "ARN of the deployed Lambda function."
  value       = aws_lambda_function.etl.arn
}

output "secret_arn" {
  description = "ARN of the Secrets Manager secret holding Idira credentials."
  value       = local.secret_arn
}

output "cursor_parameter_name" {
  description = "SSM Parameter name storing the run cursor."
  value       = aws_ssm_parameter.cursor.name
}
