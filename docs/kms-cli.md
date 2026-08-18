---
title: 5.2 AWS CLI
parent: 5. Creating Keys
nav_order: 2
---

# Creating a CMK with the AWS CLI
{: .no_toc }

The CLI is the operational path — fast, scriptable, and the only sane tool
during an incident. Everything the Console does maps to two or three commands.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## The minimum viable key

```bash
export AWS_PROFILE=keyadmin
export AWS_REGION=us-east-1

aws kms create-key \
  --description "Prod platform key for general S3 object encryption" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --origin AWS_KMS
```

```json
{
    "KeyMetadata": {
        "AWSAccountId": "111122223333",
        "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
        "Arn": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "CreationDate": "2026-08-18T14:22:31.123000-04:00",
        "Enabled": true,
        "Description": "Prod platform key for general S3 object encryption",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
        "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
        "MultiRegion": false
    }
}
```

That key is real, usable, and **wrong for production** — it has the default key
policy (full access to the account root), no alias, no rotation, and no tags.
The rest of this page fixes each of those.

## Parameter reference

| Parameter | Values | Notes |
|:--|:--|:--|
| `--key-spec` | `SYMMETRIC_DEFAULT`, `RSA_2048/3072/4096`, `ECC_NIST_P256/P384/P521`, `ECC_SECG_P256K1`, `SM2`, `HMAC_224/256/384/512` | Immutable |
| `--key-usage` | `ENCRYPT_DECRYPT`, `SIGN_VERIFY`, `GENERATE_VERIFY_MAC`, `KEY_AGREEMENT` | Immutable; must match the spec |
| `--origin` | `AWS_KMS`, `EXTERNAL`, `AWS_CLOUDHSM`, `EXTERNAL_KEY_STORE` | Immutable |
| `--multi-region` | flag | Immutable |
| `--custom-key-store-id` | `cks-…` | Requires `--origin AWS_CLOUDHSM` or `EXTERNAL_KEY_STORE` |
| `--policy` | `file://policy.json` | Defaults to root-account-full-access if omitted |
| `--bypass-policy-lockout-safety-check` | flag | **Avoid.** Exists to let you lock yourself out |
| `--tags` | `TagKey=…,TagValue=…` | Repeatable |
| `--description` | string | Mutable later via `update-key-description` |

{: .warning }
> **`--bypass-policy-lockout-safety-check` does exactly what it says.** Without
> the safety check you can write a key policy that no principal — including the
> account root — can modify. The key becomes permanently unmanageable, and AWS
> Support cannot fix it. The only recovery is deletion, which destroys everything
> the key protects. Never use this flag outside a deliberate, reviewed design.

## Build the production key properly

### 1. Write the key policy first

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
WORKLOAD_ACCOUNT="444455556666"
KEY_ADMIN_ROLE=$(aws iam list-roles \
  --query "Roles[?starts_with(RoleName,'AWSReservedSSO_KeyAdministrator')].Arn" \
  --output text)

cat > /tmp/key-policy-s3-general.json <<POLICY
{
  "Version": "2012-10-17",
  "Id": "key-policy-prod-platform-s3-general",
  "Statement": [
    {
      "Sid": "EnableIAMUserPermissions",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyAdministration",
      "Effect": "Allow",
      "Principal": { "AWS": "${KEY_ADMIN_ROLE}" },
      "Action": [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
        "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
        "kms:Get*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowWorkloadAccountUseViaS3",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${WORKLOAD_ACCOUNT}:root" },
      "Action": [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.us-east-1.amazonaws.com",
          "kms:CallerAccount": "${WORKLOAD_ACCOUNT}"
        }
      }
    },
    {
      "Sid": "AllowGrantsForAWSServices",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::${WORKLOAD_ACCOUNT}:root" },
      "Action": ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"],
      "Resource": "*",
      "Condition": {
        "Bool": { "kms:GrantIsForAWSResource": "true" }
      }
    }
  ]
}
POLICY

# Validate the JSON before you send it
jq empty /tmp/key-policy-s3-general.json && echo "policy JSON is valid"
```

{: .note }
> **`kms:GrantIsForAWSResource`** restricts grant creation to AWS services acting
> on the caller's behalf. Services like EBS, RDS, and Lambda create grants
> automatically when you attach a CMK to a resource; without this statement those
> integrations fail with a confusing permissions error. With it, the workload
> account can let AWS services create grants but cannot mint arbitrary grants to
> principals of its choosing.

### 2. Create the key with the policy and tags

```bash
KEY_ARN=$(aws kms create-key \
  --description "Prod platform key for general S3 object encryption" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --origin AWS_KMS \
  --policy file:///tmp/key-policy-s3-general.json \
  --tags TagKey=Environment,TagValue=prod \
         TagKey=DataClass,TagValue=confidential \
         TagKey=Owner,TagValue=platform@yourcompany.com \
         TagKey=CostCenter,TagValue=CC-4417 \
         TagKey=Compliance,TagValue=none \
         TagKey=ManagedBy,TagValue=cli \
  --query 'KeyMetadata.Arn' --output text)

echo "Created: $KEY_ARN"
```

### 3. Create the alias

```bash
aws kms create-alias \
  --alias-name alias/prod/platform/s3-general \
  --target-key-id "$KEY_ARN"
```

{: .tip }
> Aliases must start with `alias/` and may not start with `alias/aws/` — that
> namespace is reserved for AWS managed keys. Slashes in the rest of the name are
> allowed and are the conventional way to express hierarchy.

### 4. Enable rotation

```bash
aws kms enable-key-rotation \
  --key-id "$KEY_ARN" \
  --rotation-period-in-days 365

aws kms get-key-rotation-status --key-id "$KEY_ARN"
```

### 5. Verify end to end

```bash
# Round-trip a small payload through the key
CT=$(aws kms encrypt \
  --key-id alias/prod/platform/s3-general \
  --plaintext "$(echo -n 'canary-value' | base64)" \
  --encryption-context purpose=smoke-test \
  --query CiphertextBlob --output text)

aws kms decrypt \
  --ciphertext-blob "fileb://<(echo "$CT" | base64 -d)" \
  --encryption-context purpose=smoke-test \
  --query Plaintext --output text | base64 -d
# -> canary-value
```

If your shell does not support process substitution, use a temp file:

```bash
echo "$CT" | base64 -d > /tmp/ct.bin
aws kms decrypt --ciphertext-blob fileb:///tmp/ct.bin \
  --encryption-context purpose=smoke-test \
  --query Plaintext --output text | base64 -d; echo
rm -f /tmp/ct.bin
```

{: .important }
> **Try the decrypt *without* the encryption context** and confirm it fails. That
> failure is the proof that encryption context is actually binding, which is the
> control you will point an auditor at:
>
> ```text
> An error occurred (InvalidCiphertextException) when calling the Decrypt operation
> ```

## A complete, idempotent provisioning script

Real operations need re-runnable scripts. This one creates the key only if the
alias does not already exist, and is safe to run in a loop.

```bash
#!/usr/bin/env bash
# scripts/create_cmk.sh — idempotent CMK provisioning
set -euo pipefail

ALIAS="${1:?usage: create_cmk.sh <alias-suffix> <description> [key-spec]}"
DESCRIPTION="${2:?}"
KEY_SPEC="${3:-SYMMETRIC_DEFAULT}"
POLICY_FILE="${POLICY_FILE:-}"
ROTATION_DAYS="${ROTATION_DAYS:-365}"

FULL_ALIAS="alias/${ALIAS}"
REGION="${AWS_REGION:-us-east-1}"

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

# --- Idempotency: does the alias already point at a key? ---------------------
EXISTING=$(aws kms list-aliases --region "$REGION" \
  --query "Aliases[?AliasName=='${FULL_ALIAS}'].TargetKeyId" --output text)

if [ -n "$EXISTING" ] && [ "$EXISTING" != "None" ]; then
  log "Alias ${FULL_ALIAS} already targets ${EXISTING} — nothing to do."
  aws kms describe-key --key-id "$FULL_ALIAS" --region "$REGION" \
    --query 'KeyMetadata.{Arn:Arn,State:KeyState,Spec:KeySpec}'
  exit 0
fi

log "Creating key for ${FULL_ALIAS} (spec=${KEY_SPEC})"

CREATE_ARGS=(
  --description "$DESCRIPTION"
  --key-spec    "$KEY_SPEC"
  --origin      AWS_KMS
  --region      "$REGION"
  --tags "TagKey=Environment,TagValue=${ENVIRONMENT:-prod}"
         "TagKey=Owner,TagValue=${OWNER:-platform@yourcompany.com}"
         "TagKey=ManagedBy,TagValue=cli"
         "TagKey=Alias,TagValue=${ALIAS}"
)

# Key usage must match the spec
case "$KEY_SPEC" in
  HMAC_*) CREATE_ARGS+=(--key-usage GENERATE_VERIFY_MAC) ;;
  ECC_*)  CREATE_ARGS+=(--key-usage SIGN_VERIFY) ;;
  *)      CREATE_ARGS+=(--key-usage ENCRYPT_DECRYPT) ;;
esac

[ -n "$POLICY_FILE" ] && CREATE_ARGS+=(--policy "file://${POLICY_FILE}")

KEY_ARN=$(aws kms create-key "${CREATE_ARGS[@]}" \
  --query 'KeyMetadata.Arn' --output text)
log "Created ${KEY_ARN}"

aws kms create-alias --region "$REGION" \
  --alias-name "$FULL_ALIAS" --target-key-id "$KEY_ARN"
log "Aliased as ${FULL_ALIAS}"

# Rotation is only supported for symmetric KMS-origin keys
if [ "$KEY_SPEC" = "SYMMETRIC_DEFAULT" ]; then
  aws kms enable-key-rotation --region "$REGION" \
    --key-id "$KEY_ARN" --rotation-period-in-days "$ROTATION_DAYS"
  log "Rotation enabled (${ROTATION_DAYS}d)"
else
  log "Rotation not applicable for ${KEY_SPEC} — skipping"
fi

log "Done: ${KEY_ARN}"
```

Run it:

```bash
chmod +x scripts/create_cmk.sh

POLICY_FILE=/tmp/key-policy-s3-general.json \
  ./scripts/create_cmk.sh prod/platform/s3-general \
  "Prod platform key for general S3 object encryption"

./scripts/create_cmk.sh prod/signing/artifact-sign \
  "Build artifact signing key" ECC_NIST_P384

./scripts/create_cmk.sh prod/integrity/token-mac \
  "Session token MAC key" HMAC_256
```

{: .tip }
> **Rotation only applies to symmetric, KMS-origin keys.** Calling
> `enable-key-rotation` on an asymmetric or HMAC key returns
> `UnsupportedOperationException`. The `case` block above is not defensive
> padding — it is required for the script to be re-runnable across key types.

## Useful day-two CLI operations

```bash
# List every customer managed key with its alias, state, and spec
aws kms list-aliases --query 'Aliases[?starts_with(AliasName,`alias/prod`)]' --output table

# Full inventory with rotation status (the auditor's favorite table)
for KEY in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  META=$(aws kms describe-key --key-id "$KEY" \
    --query 'KeyMetadata.{Mgr:KeyManager,State:KeyState,Spec:KeySpec,MR:MultiRegion}' \
    --output json 2>/dev/null) || continue
  [ "$(echo "$META" | jq -r .Mgr)" != "CUSTOMER" ] && continue
  ROT=$(aws kms get-key-rotation-status --key-id "$KEY" \
    --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "n/a")
  ALIAS=$(aws kms list-aliases --key-id "$KEY" \
    --query 'Aliases[0].AliasName' --output text 2>/dev/null)
  printf '%-24s %-46s rotation=%s state=%s\n' \
    "${ALIAS:-<no alias>}" "$KEY" "$ROT" "$(echo "$META" | jq -r .State)"
done

# Who can use this key? (dump the policy)
aws kms get-key-policy --key-id alias/prod/platform/s3-general \
  --policy-name default --output text | jq .

# Disable a key immediately (reversible — the incident-response first move)
aws kms disable-key --key-id alias/prod/platform/s3-general

# Re-enable
aws kms enable-key --key-id alias/prod/platform/s3-general

# Retarget an alias to a different key (emergency key replacement)
aws kms update-alias \
  --alias-name alias/prod/platform/s3-general \
  --target-key-id "$NEW_KEY_ARN"
```

{: .warning }
> **`disable-key` breaks decryption of everything that key protects, instantly.**
> That is the point — it is the containment action for a suspected key
> compromise. But it is not free: running services will start throwing
> `KMSInvalidStateException` within seconds. Know which workloads depend on a key
> *before* you disable it. The dependency map lives in
> [Verification &amp; Runbook]({% link docs/verification.md %}).

---

[Next: 5.3 Terraform]({% link docs/kms-terraform.md %}){: .btn .btn-primary }
