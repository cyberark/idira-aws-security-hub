#!/usr/bin/env bash
# update_lambda.sh – Rebuild and update an already-deployed Lambda's code
# without redeploying the CloudFormation stack.
#
# Usage:
#   ./deploy/update_lambda.sh <s3-bucket> [stack-name] [aws-region] [aws-profile]
#
# Examples:
#   ./deploy/update_lambda.sh my-artifacts-bucket
#   ./deploy/update_lambda.sh my-artifacts-bucket idira-audit-securityhub us-east-1
#   ./deploy/update_lambda.sh my-artifacts-bucket idira-audit-prod us-west-2 my-aws-profile
set -euo pipefail

BUCKET="${1:?Usage: update_lambda.sh <s3-bucket> [stack-name] [aws-region] [aws-profile]}"
STACK="${2:-idira-audit-securityhub}"
REGION="${3:-us-east-1}"
PROFILE="${4:-}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAMBDA_DIR="$REPO_ROOT/lambda"
DEPLOY_DIR="$REPO_ROOT/deploy"
ZIP_NAME="idira-audit-securityhub.zip"
ZIP_PATH="$DEPLOY_DIR/$ZIP_NAME"
DEPS_ZIP="$DEPLOY_DIR/lambda-deps.zip"
FUNCTION_NAME="idira-audit-securityhub-${STACK}"

PROFILE_ARGS=()
if [[ -n "$PROFILE" ]]; then
  PROFILE_ARGS=(--profile "$PROFILE")
fi

echo "==> Building Lambda package..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# Unpack the pre-packaged dependencies (no pip at deploy time). See build.sh
# and deploy/make_deps.sh for why: the required preview boto3/botocore build is
# not installable from PyPI. Regenerate with ./deploy/make_deps.sh when deps change.
if [[ ! -f "$DEPS_ZIP" ]]; then
  echo "ERROR: $DEPS_ZIP not found. Run ./deploy/make_deps.sh first." >&2
  exit 1
fi
echo "    Unpacking pre-packaged dependencies from $(basename "$DEPS_ZIP")..."
unzip -q "$DEPS_ZIP" -d "$BUILD_DIR/"

rsync -a \
  --exclude='.env' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='*.json' \
  --exclude='*.csv' \
  --exclude='tests/' \
  --exclude='conftest.py' \
  --exclude='.audit_cursor' \
  "$LAMBDA_DIR/" "$BUILD_DIR/"

echo "==> Creating $ZIP_NAME..."
(cd "$BUILD_DIR" && zip -r "$ZIP_PATH" . -x "*.pyc" -x "*__pycache__*" > /dev/null)
echo "    Package size: $(du -sh "$ZIP_PATH" | cut -f1)"

echo "==> Uploading to s3://$BUCKET/$ZIP_NAME ..."
aws s3 cp "$ZIP_PATH" "s3://$BUCKET/$ZIP_NAME" \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}"

echo "==> Updating Lambda function code: $FUNCTION_NAME ..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --s3-bucket "$BUCKET" \
  --s3-key "$ZIP_NAME" \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}" \
  --output text --query 'LastUpdateStatus'

echo "==> Waiting for function update to complete..."
aws lambda wait function-updated \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}"

echo "==> Ensuring PYTHONPATH=/var/task in environment..."
CURRENT_ENV=$(aws lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}" \
  --query 'Environment.Variables' --output json)

UPDATED_ENV=$(echo "$CURRENT_ENV" | python3 -c "
import sys, json
env = json.load(sys.stdin)
env['PYTHONPATH'] = '/var/task'
env['AWS_DATA_PATH'] = '/var/task/botocore/data'
print(json.dumps({'Variables': env}))
")

aws lambda update-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --environment "$UPDATED_ENV" \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}" \
  --output text --query 'LastUpdateStatus'

echo ""
echo "Done. Lambda '$FUNCTION_NAME' updated."
