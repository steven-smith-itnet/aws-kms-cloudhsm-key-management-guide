---
title: 7.5 Multi-Region Keys
parent: 7. Key Operations
nav_order: 5
---

# Multi-Region Keys
{: .no_toc }

The only way to decrypt in Region B something that was encrypted in Region A —
and therefore a prerequisite for most cross-Region disaster recovery.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## The problem they solve

```text
WITHOUT multi-Region keys

  us-east-1                              us-west-2
  ┌──────────────────────┐               ┌──────────────────────┐
  │ key/aaaa-1111        │               │ key/bbbb-2222        │
  │  encrypts obj.dat ───┼──replicate──▶ │  ✗ cannot decrypt    │
  └──────────────────────┘               └──────────────────────┘
                                          Different key material.
                                          The DR copy is unreadable.

WITH multi-Region keys

  us-east-1 (primary)                    us-west-2 (replica)
  ┌──────────────────────┐               ┌──────────────────────┐
  │ key/mrk-1234…        │               │ key/mrk-1234…        │
  │  encrypts obj.dat ───┼──replicate──▶ │  ✓ decrypts          │
  └──────────────────────┘               └──────────────────────┘
   Same key ID suffix, same key material, independent policies.
```

{: .important }
> **Multi-Region is immutable and must be chosen at creation.** A single-Region
> key can never be converted. If you might ever need cross-Region DR for the data
> a key protects, create it as multi-Region now — the cost of doing so
> unnecessarily is a slightly higher monthly charge per replica, and the cost of
> *not* doing so is re-encrypting a production dataset under time pressure.

## What is and is not shared

| Property | Shared across replicas | Notes |
|:--|:--|:--|
| Key material | ✅ Yes | This is the whole point |
| Key ID suffix | ✅ Yes | `mrk-1234abcd…` in every Region |
| Key spec / usage / origin | ✅ Yes | Replicas inherit them |
| Rotation state and backing keys | ✅ Yes | Managed on the primary, propagates |
| Full ARN | ❌ No | The Region differs |
| Key policy | ❌ No | **Independently editable per Region** |
| Grants | ❌ No | Per-Region |
| Tags | ❌ No | Per-Region |
| Aliases | ❌ No | Create one in each Region |
| Enabled/disabled state | ❌ No | Per-Region |

{: .warning }
> **Independent key policies are a footgun as much as a feature.** A replica can
> be given a *broader* policy than its primary. Nothing stops someone from
> creating a replica in a Region with lax controls and granting it widely — and
> that replica decrypts every ciphertext the primary ever produced. Constrain
> `kms:ReplicateKey` with an SCP that limits `kms:ReplicaRegion` to your approved
> Regions.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyReplicationOutsideApprovedRegions",
    "Effect": "Deny",
    "Action": "kms:ReplicateKey",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "kms:ReplicaRegion": ["us-east-1", "us-west-2", "eu-west-1"]
      }
    }
  }]
}
```

## Creating a multi-Region key

```bash
export AWS_REGION=us-east-1

PRIMARY_ARN=$(aws kms create-key \
  --multi-region \
  --description "Prod RDS storage encryption key (multi-Region primary)" \
  --key-spec SYMMETRIC_DEFAULT \
  --key-usage ENCRYPT_DECRYPT \
  --policy file:///tmp/key-policy-rds.json \
  --tags TagKey=Environment,TagValue=prod \
         TagKey=DataClass,TagValue=restricted \
         TagKey=ManagedBy,TagValue=cli \
  --query 'KeyMetadata.Arn' --output text)

aws kms create-alias --alias-name alias/prod/data/rds-primary \
  --target-key-id "$PRIMARY_ARN"
aws kms enable-key-rotation --key-id "$PRIMARY_ARN" --rotation-period-in-days 365

echo "$PRIMARY_ARN"
# arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab
```

Note the `mrk-` prefix — that is how you identify a multi-Region key at a glance.

## Replicating

```bash
REPLICA_ARN=$(aws kms replicate-key \
  --key-id "$PRIMARY_ARN" \
  --replica-region us-west-2 \
  --description "Prod RDS storage encryption key (us-west-2 replica)" \
  --policy file:///tmp/key-policy-rds.json \
  --tags TagKey=Environment,TagValue=prod \
         TagKey=DataClass,TagValue=restricted \
         TagKey=Role,TagValue=replica \
  --query 'ReplicaKeyMetadata.Arn' --output text)

# The alias must be created separately in the replica Region
aws kms create-alias --region us-west-2 \
  --alias-name alias/prod/data/rds-primary \
  --target-key-id "$REPLICA_ARN"

aws kms describe-key --region us-west-2 --key-id "$REPLICA_ARN" \
  --query 'KeyMetadata.{Arn:Arn,State:KeyState,MR:MultiRegion,Config:MultiRegionConfiguration}'
```

```json
{
    "Arn": "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",
    "State": "Enabled",
    "MR": true,
    "Config": {
        "MultiRegionKeyType": "REPLICA",
        "PrimaryKey": {
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd…",
            "Region": "us-east-1"
        },
        "ReplicaKeys": [
            { "Arn": "arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd…",
              "Region": "us-west-2" }
        ]
    }
}
```

{: .note }
> A replica can briefly report `KeyState: Creating` while KMS synchronizes key
> material. `aws kms describe-key` polling until `Enabled` is the correct wait —
> there is no dedicated waiter.

## Proving it works

The acceptance test for a multi-Region key is a cross-Region round trip.

```bash
# Encrypt in us-east-1
CT=$(aws kms encrypt --region us-east-1 \
  --key-id alias/prod/data/rds-primary \
  --plaintext "$(echo -n 'cross-region-canary' | base64)" \
  --encryption-context purpose=dr-test \
  --query CiphertextBlob --output text)

echo "$CT" | base64 -d > /tmp/mrk-test.bin

# Decrypt in us-west-2 — same ciphertext, different Region, no re-encryption
aws kms decrypt --region us-west-2 \
  --ciphertext-blob fileb:///tmp/mrk-test.bin \
  --encryption-context purpose=dr-test \
  --query Plaintext --output text | base64 -d; echo

rm -f /tmp/mrk-test.bin
```

```text
cross-region-canary
```

{: .tip }
> Run this as a scheduled canary, not just once at build time. It is the only
> test that actually proves your DR Region can read production data, and it costs
> two KMS requests a day. Wire the failure to a page — see
> [Monitoring]({% link docs/monitoring.md %}).

## Promoting a replica during a Region failure

If the primary Region is unavailable, a replica can be promoted so that key
administration continues.

```bash
# Run this in the surviving Region
aws kms update-primary-region \
  --region us-west-2 \
  --key-id arn:aws:kms:us-west-2:111122223333:key/mrk-1234abcd… \
  --primary-region us-west-2

aws kms describe-key --region us-west-2 --key-id alias/prod/data/rds-primary \
  --query 'KeyMetadata.MultiRegionConfiguration.MultiRegionKeyType'
# -> "PRIMARY"
```

{: .important }
> **You do not need to promote a replica in order to decrypt.** Replicas serve
> cryptographic operations independently at all times; if `us-east-1` is down,
> `us-west-2` keeps decrypting without any action from you. Promotion only moves
> the *administrative* functions — rotation management and the ability to create
> further replicas. Do not put "promote the KMS replica" on the critical path of
> your failover runbook; put it on the recovery checklist afterwards.

## Terraform

```hcl
provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "west"
  region = "us-west-2"
}

data "aws_iam_policy_document" "rds_key" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111122223333:root"]
    }
  }
  statement {
    sid    = "AllowWorkloadUse"
    effect = "Allow"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
      "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::444455556666:root"]
    }
  }
  statement {
    sid       = "AllowGrantsForAWSResources"
    effect    = "Allow"
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::444455556666:root"]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "rds_primary" {
  description             = "Prod RDS storage encryption key (multi-Region primary)"
  multi_region            = true
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.rds_key.json

  tags = { Environment = "prod", DataClass = "restricted", Role = "primary" }

  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "rds_primary" {
  name          = "alias/prod/data/rds-primary"
  target_key_id = aws_kms_key.rds_primary.key_id
}

resource "aws_kms_replica_key" "rds_west" {
  provider = aws.west

  description             = "Prod RDS storage encryption key (us-west-2 replica)"
  primary_key_arn         = aws_kms_key.rds_primary.arn
  deletion_window_in_days = 30
  # Deliberately the SAME policy document — do not let the replica drift wider.
  policy                  = data.aws_iam_policy_document.rds_key.json

  tags = { Environment = "prod", DataClass = "restricted", Role = "replica" }

  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "rds_west" {
  provider      = aws.west
  name          = "alias/prod/data/rds-primary"
  target_key_id = aws_kms_replica_key.rds_west.key_id
}
```

## Cost and design guidance

| | Single-Region key | Multi-Region key |
|:--|:--|:--|
| Monthly charge | One key | **Per Region** — primary + each replica |
| Request charge | Per Region where used | Per Region where used |
| Rotation | Independent | Managed on the primary |
| Blast radius | One Region | Everywhere it is replicated |

{: .warning }
> **Multi-Region keys widen the blast radius by design.** Compromise of the key
> material — or of a principal allowed to use a replica — affects every Region.
> Use them where cross-Region decryption is a genuine requirement (DR, global
> tables, cross-Region backup), and use single-Region keys everywhere else. A
> blanket "make everything multi-Region" policy is the wrong default.

### When to use which

| Scenario | Choice |
|:--|:--|
| DynamoDB global tables | Multi-Region — required |
| Cross-Region S3 replication of encrypted objects | Multi-Region (or re-encrypt at the destination) |
| Cross-Region RDS/Aurora read replicas or snapshot copies | Multi-Region |
| Cross-Region EBS/AMI snapshot copies for DR | Multi-Region |
| Secrets Manager multi-Region secret replicas | Multi-Region |
| A workload that lives entirely in one Region | **Single-Region** |
| Regulatory data-residency requirement pinning data to one Region | **Single-Region**, and add an SCP denying `kms:ReplicateKey` |

---

[Next: 8. CloudHSM &amp; HSM-Backed Tiers]({% link docs/cloudhsm.md %}){: .btn .btn-primary }
