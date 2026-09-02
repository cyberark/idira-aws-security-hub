# Deployment

> **Interim packaging.** This version of the integration ships a **pre-built
> dependency package** (`deploy/lambda-deps.zip`) rather than installing
> dependencies at deploy time. This is a deliberate interim solution: it exists
> only because the integration depends on a preview-specific Security Hub API
> (`BatchImportFindingsV2` / `GetFindingsV2`) that is not yet generally
> available. Once that API goes GA, this pre-built package can be dropped in
> favour of standard dependency installation — see
> *[Removing the preview dependency once the API is GA](#removing-the-preview-dependency-once-the-api-is-ga)*.

The Lambda is packaged as a single zip (`PYTHONPATH=/var/task`, `AWS_DATA_PATH=/var/task/botocore/data`)
and deployed to the customer's AWS account.

## Why dependencies are pre-packaged (no pip at deploy)

This project requires a **preview build** of `boto3` / `botocore` `1.42.49` that
ships the Security Hub `BatchImportFindingsV2` / `GetFindingsV2` service models.
That build is **not on PyPI**, and — critically — PyPI has a *different* wheel
that also calls itself `1.42.49`. So `pip install boto3==1.42.49` at deploy time
would silently pull the GA wheel that **lacks those APIs**, and the customer
deploy would break.

To remove that risk, deployment never runs pip. Instead:

- `vendor/` — the exact wheels, committed to the repo. This includes the
  preview `boto3`/`botocore` (which can't be re-fetched) plus the pinned GA
  runtime deps, so the archive can be rebuilt fully offline.
- `lambda-deps.zip` — the pre-built dependency tree, committed. `build.sh` and
  `update_lambda.sh` simply `unzip` it into the package. Built by `make_deps.sh`.

## Regenerating the dependency archive

Only needed when the vendored wheels change:

```bash
./deploy/make_deps.sh      # rebuilds deploy/lambda-deps.zip offline from vendor/
git add deploy/vendor deploy/lambda-deps.zip
```

`make_deps.sh` targets the Lambda `python3.12` / `manylinux2014_x86_64` runtime
and fails loudly if the vendored botocore is the GA build rather than the
preview (it checks for `BatchImportFindingsV2` / `GetFindingsV2`).

## Deploy

```bash
./deploy/build.sh <s3-bucket> [stack-name] [region] [profile]        # first deploy (CFN)
./deploy/update_lambda.sh <s3-bucket> [stack-name] [region] [profile] # code update only
```

## Removing the preview dependency once the API is GA

When `BatchImportFindingsV2` is GA in the Lambda runtime SDK:

1. Re-vendor GA `boto3`/`botocore` from PyPI (or drop them and rely on the
   runtime-provided SDK) and rerun `make_deps.sh`.
2. Remove the `_DirectHttpTransport` fallback in `lambda/aws/security_hub.py`.
