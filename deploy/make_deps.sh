#!/usr/bin/env bash
# make_deps.sh – Build the pre-packaged Lambda dependency archive from the
# vendored wheels in deploy/vendor/, fully offline (no PyPI, no network).
#
# WHY THIS EXISTS
#   This project depends on a *preview* build of boto3/botocore 1.42.49 that
#   ships the Security Hub BatchImportFindingsV2 / GetFindingsV2 service models.
#   That preview build is NOT on PyPI. Worse, PyPI has a *different* wheel that
#   also calls itself 1.42.49, so `pip install boto3==1.42.49` at deploy time
#   would silently pull the GA wheel that LACKS those APIs. To avoid that trap
#   entirely, deployment never runs pip: it unpacks the archive this script
#   produces. Regenerate the archive only when the vendored wheels change.
#
# Usage:
#   ./deploy/make_deps.sh
#
# Output:
#   deploy/lambda-deps.zip   (committed to the repo; consumed by build.sh /
#                             update_lambda.sh)
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$DEPLOY_DIR/vendor"
DEPS_ZIP="$DEPLOY_DIR/lambda-deps.zip"

# Lambda python3.12 runtime target. Wheels must match this platform for any
# package with compiled extensions (e.g. charset-normalizer).
PY_VERSION="3.12"
PLATFORM="manylinux2014_x86_64"

if [[ ! -d "$VENDOR_DIR" ]] || ! ls "$VENDOR_DIR"/*.whl >/dev/null 2>&1; then
  echo "ERROR: no wheels found in $VENDOR_DIR" >&2
  echo "       The preview boto3/botocore wheels must be committed there." >&2
  exit 1
fi

echo "==> Installing vendored wheels into a staging tree (offline)..."
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

# --no-index + --find-links => never touch the network. --platform pins the
# target ABI so compiled wheels resolve to the Lambda runtime, not the host.
pip install \
  --no-index \
  --find-links "$VENDOR_DIR" \
  --platform "$PLATFORM" \
  --python-version "$PY_VERSION" \
  --implementation cp \
  --only-binary=:all: \
  --target "$STAGE_DIR" \
  boto3 botocore s3transfer jmespath python-dateutil six urllib3 \
  requests certifi charset-normalizer idna python-dotenv

echo "==> Sanity-checking the preview Security Hub V2 API models are present..."
if [[ ! -f "$STAGE_DIR/botocore/data/securityhub/2018-10-26/service-2.json.gz" ]]; then
  echo "ERROR: securityhub service model missing from staged botocore." >&2
  exit 1
fi
if ! python3 - "$STAGE_DIR" <<'PY'
import gzip, json, sys, pathlib
stage = pathlib.Path(sys.argv[1])
model = stage / "botocore/data/securityhub/2018-10-26/service-2.json.gz"
ops = json.loads(gzip.open(model).read())["operations"]
required = {"BatchImportFindingsV2", "GetFindingsV2"}
missing = required - ops.keys()
if missing:
    print(f"ERROR: staged botocore is not the preview build; missing ops: {missing}", file=sys.stderr)
    sys.exit(1)
print("    OK: preview botocore with BatchImportFindingsV2 / GetFindingsV2 confirmed.")
PY
then
  echo "ERROR: vendored botocore is the GA build, not the preview. Re-vendor the preview wheel." >&2
  exit 1
fi

echo "==> Creating $DEPS_ZIP ..."
rm -f "$DEPS_ZIP"
(cd "$STAGE_DIR" && zip -rq "$DEPS_ZIP" . -x "*.pyc" -x "*__pycache__*" -x "*.dist-info/RECORD")
echo "    Archive size: $(du -sh "$DEPS_ZIP" | cut -f1)"
echo ""
echo "Done. Commit deploy/lambda-deps.zip. build.sh / update_lambda.sh unpack it (no pip at deploy)."
