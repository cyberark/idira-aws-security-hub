#!/usr/bin/env bash
# build.sh – Package the Lambda, upload to S3, and deploy the CloudFormation stack.
#
# Usage:
#   ./deploy/build.sh <s3-bucket> [stack-name] [aws-region] [aws-profile]
#
# Examples:
#   ./deploy/build.sh my-artifacts-bucket
#   ./deploy/build.sh my-artifacts-bucket idira-audit-securityhub us-east-1
#   ./deploy/build.sh my-artifacts-bucket idira-audit-prod us-west-2 my-aws-profile
set -euo pipefail

BUCKET="${1:?Usage: build.sh <s3-bucket> [stack-name] [aws-region] [aws-profile]}"
STACK="${2:-idira-audit-securityhub}"
REGION="${3:-us-east-1}"
PROFILE="${4:-}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAMBDA_DIR="$REPO_ROOT/lambda"
DEPLOY_DIR="$REPO_ROOT/deploy"
ZIP_NAME="idira-audit-securityhub.zip"
ZIP_PATH="$DEPLOY_DIR/$ZIP_NAME"
DEPS_ZIP="$DEPLOY_DIR/lambda-deps.zip"

PROFILE_ARGS=()
if [[ -n "$PROFILE" ]]; then
  PROFILE_ARGS=(--profile "$PROFILE")
fi

echo "==> Building Lambda package..."
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# Unpack the pre-packaged dependencies. We deliberately DO NOT run pip here:
# this project needs a preview boto3/botocore build (BatchImportFindingsV2 /
# GetFindingsV2) that is not on PyPI and whose version number collides with a
# different GA wheel. deploy/lambda-deps.zip is built offline by make_deps.sh
# from the vendored wheels. Regenerate it with ./deploy/make_deps.sh when the
# dependencies change.
if [[ ! -f "$DEPS_ZIP" ]]; then
  echo "ERROR: $DEPS_ZIP not found. Run ./deploy/make_deps.sh first." >&2
  exit 1
fi
echo "    Unpacking pre-packaged dependencies from $(basename "$DEPS_ZIP")..."
unzip -q "$DEPS_ZIP" -d "$BUILD_DIR/"

# Copy Lambda source (exclude local-only files)
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

echo "==> Deploying CloudFormation stack '$STACK'..."
aws cloudformation deploy \
  --template-file "$DEPLOY_DIR/cfn/template.yaml" \
  --stack-name "$STACK" \
  --parameter-overrides \
      ArtifactsBucket="$BUCKET" \
      ArtifactsKey="$ZIP_NAME" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$REGION" \
  "${PROFILE_ARGS[@]}"

echo ""
echo "==> Stack outputs:"
aws cloudformation describe-stacks \
  --stack-name "$STACK" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs' \
  --output table \
  "${PROFILE_ARGS[@]}"

echo ""
echo "Done. Next step: populate the Secrets Manager secret with real Idira credentials."
echo "Secret ARN is listed in the 'SecretArn' output above."
