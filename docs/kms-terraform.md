---
title: 5.3 Terraform
parent: 5. Creating Keys
nav_order: 3
---

# Creating a CMK with Terraform
{: .no_toc }

The production path. A reviewed, versioned, reusable module that produces
identical keys across environments and accounts.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## The reusable module

Put this in `modules/kms-key/`. It handles single- and multi-Region keys,
key-type-aware rotation, cross-account use, and the service-grant statement that
so many hand-written policies forget.

### `modules/kms-key/variables.tf`

```hcl
variable "alias" {
  description = "Alias suffix, without the leading 'alias/'. e.g. prod/platform/s3-general"
  type        = string

  validation {
    condition     = !startswith(var.alias, "alias/")
    error_message = "Provide the suffix only — the module prepends 'alias/'."
  }
  validation {
    condition     = !startswith(var.alias, "aws/")
    error_message = "The 'aws/' alias namespace is reserved for AWS managed keys."
  }
}

variable "description" {
  description = "Human-readable purpose of the key. Shows in the Console and in audits."
  type        = string
}

variable "key_spec" {
  description = "KMS key spec."
  type        = string
  default     = "SYMMETRIC_DEFAULT"

  validation {
    condition = contains([
      "SYMMETRIC_DEFAULT",
      "RSA_2048", "RSA_3072", "RSA_4096",
      "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1",
      "HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512",
      "SM2",
    ], var.key_spec)
    error_message = "Unsupported key_spec."
  }
}

variable "key_usage" {
  description = "ENCRYPT_DECRYPT, SIGN_VERIFY, or GENERATE_VERIFY_MAC."
  type        = string
  default     = "ENCRYPT_DECRYPT"
}

variable "multi_region" {
  description = "Create as a multi-Region primary key. IMMUTABLE after creation."
  type        = bool
  default     = false
}

variable "enable_rotation" {
  description = "Enable automatic rotation. Only valid for symmetric KMS-origin keys."
  type        = bool
  default     = true
}

variable "rotation_period_days" {
  description = "Rotation interval, 90-2560 days."
  type        = number
  default     = 365

  validation {
    condition     = var.rotation_period_days >= 90 && var.rotation_period_days <= 2560
    error_message = "rotation_period_days must be between 90 and 2560."
  }
}

variable "deletion_window_days" {
  description = "Waiting period before a scheduled deletion completes, 7-30 days."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_days >= 7 && var.deletion_window_days <= 30
    error_message = "deletion_window_days must be between 7 and 30."
  }
}

variable "key_administrator_arns" {
  description = "Principals allowed to administer (but not use) the key."
  type        = list(string)
  default     = []
}

variable "key_user_arns" {
  description = "Principals in this account allowed to perform cryptographic operations."
  type        = list(string)
  default     = []
}

variable "cross_account_user_arns" {
  description = "Principals (or account roots) in other accounts allowed to use the key."
  type        = list(string)
  default     = []
}

variable "via_services" {
  description = "Restrict use to these AWS services, e.g. [\"s3.us-east-1.amazonaws.com\"]. Empty = unrestricted."
  type        = list(string)
  default     = []
}

variable "custom_key_store_id" {
  description = "Optional CloudHSM-backed custom key store ID."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to the key."
  type        = map(string)
  default     = {}
}
```

### `modules/kms-key/main.tf`

```hcl
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  root_arn   = "arn:${local.partition}:iam::${local.account_id}:root"

  # Rotation is only meaningful for symmetric, KMS-origin keys.
  rotation_supported = var.key_spec == "SYMMETRIC_DEFAULT" && var.custom_key_store_id == null
  rotation_effective = var.enable_rotation && local.rotation_supported

  # Only attach the ViaService condition when the caller asked for it.
  via_service_condition = length(var.via_services) > 0 ? [{
    test     = "StringEquals"
    variable = "kms:ViaService"
    values   = var.via_services
  }] : []
}

# ---------------------------------------------------------------------------
# Key policy — built with the IAM policy document data source so that the
# statements are validated at plan time rather than rejected at apply time.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "key" {
  # 1. The account root must retain kms:* or the key becomes unmanageable.
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  # 2. Key administration — lifecycle, never cryptographic use.
  dynamic "statement" {
    for_each = length(var.key_administrator_arns) > 0 ? [1] : []
    content {
      sid    = "AllowKeyAdministration"
      effect = "Allow"
      actions = [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
        "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
        "kms:Get*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        "kms:ReplicateKey", "kms:RotateKeyOnDemand",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.key_administrator_arns
      }
    }
  }

  # 3. Cryptographic use, in this account.
  dynamic "statement" {
    for_each = length(var.key_user_arns) > 0 ? [1] : []
    content {
      sid    = "AllowKeyUse"
      effect = "Allow"
      actions = [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey",
        "kms:Sign", "kms:Verify", "kms:GenerateMac", "kms:VerifyMac",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.key_user_arns
      }
      dynamic "condition" {
        for_each = local.via_service_condition
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }

  # 4. Cryptographic use, from other accounts.
  dynamic "statement" {
    for_each = length(var.cross_account_user_arns) > 0 ? [1] : []
    content {
      sid    = "AllowCrossAccountKeyUse"
      effect = "Allow"
      actions = [
        "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
        "kms:GenerateDataKey*", "kms:DescribeKey",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.cross_account_user_arns
      }
      dynamic "condition" {
        for_each = local.via_service_condition
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }

  # 5. Let AWS services create grants on behalf of cross-account principals.
  #    Without this, attaching the CMK to EBS/RDS/Lambda in the workload
  #    account fails with an opaque AccessDenied.
  dynamic "statement" {
    for_each = length(var.cross_account_user_arns) > 0 ? [1] : []
    content {
      sid       = "AllowGrantsForAWSResources"
      effect    = "Allow"
      actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.cross_account_user_arns
      }
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  description              = var.description
  key_usage                = var.key_usage
  customer_master_key_spec = var.key_spec
  multi_region             = var.multi_region
  custom_key_store_id      = var.custom_key_store_id

  enable_key_rotation     = local.rotation_effective
  rotation_period_in_days = local.rotation_effective ? var.rotation_period_days : null
  deletion_window_in_days = var.deletion_window_days

  policy = data.aws_iam_policy_document.key.json

  tags = merge(var.tags, {
    Alias     = var.alias
    ManagedBy = "terraform"
  })

  lifecycle {
    # A key is a stateful resource protecting real data. Never let a plan
    # replace one silently.
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}
```

{: .important }
> **`prevent_destroy = true` is the most important line in this module.** A
> refactor that renames a module instance, or a `terraform destroy` run against
> the wrong workspace, would otherwise schedule your production keys for
> deletion. With it, Terraform refuses the plan outright. When you genuinely need
> to remove a key, do it deliberately: remove the lifecycle block in its own
> reviewed commit, then apply.

### `modules/kms-key/outputs.tf`

```hcl
output "key_id" {
  description = "The KMS key ID (UUID)."
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "The full key ARN — use this for cross-account references."
  value       = aws_kms_key.this.arn
}

output "alias_name" {
  description = "The alias, including the 'alias/' prefix."
  value       = aws_kms_alias.this.name
}

output "alias_arn" {
  description = "The alias ARN."
  value       = aws_kms_alias.this.arn
}

output "rotation_enabled" {
  description = "Whether automatic rotation is active on this key."
  value       = aws_kms_key.this.enable_key_rotation
}
```

## Using the module

### `environments/security-prod/keys.tf`

```hcl
locals {
  workload_account_id = "444455556666"
  workload_root       = "arn:aws:iam::${local.workload_account_id}:root"

  # Resolved below from the SSO-provisioned role, whose name carries a random suffix
  key_admins = tolist(data.aws_iam_roles.key_admin.arns)

  common_tags = {
    Owner      = "platform@yourcompany.com"
    CostCenter = "CC-4417"
    Repository = "aws-key-management"
  }
}

# Resolve the SSO-provisioned role ARN rather than hard-coding the random suffix
data "aws_iam_roles" "key_admin" {
  name_regex  = "AWSReservedSSO_KeyAdministrator_.*"
  path_prefix = "/aws-reserved/sso.amazonaws.com/"
}

# --- General-purpose S3 key --------------------------------------------------
module "s3_general" {
  source = "../../modules/kms-key"

  alias       = "prod/platform/s3-general"
  description = "Prod platform key for general S3 object encryption"

  key_administrator_arns  = local.key_admins
  cross_account_user_arns = [local.workload_root]
  via_services            = ["s3.${var.region}.amazonaws.com"]

  enable_rotation      = true
  rotation_period_days = 365
  deletion_window_days = 30

  tags = merge(local.common_tags, {
    Environment = "prod"
    DataClass   = "confidential"
    Compliance  = "none"
  })
}

# --- EBS default encryption key ---------------------------------------------
module "ebs_default" {
  source = "../../modules/kms-key"

  alias       = "prod/platform/ebs-default"
  description = "Prod default EBS volume encryption key"

  key_administrator_arns  = local.key_admins
  cross_account_user_arns = [local.workload_root]
  via_services            = ["ec2.${var.region}.amazonaws.com"]

  tags = merge(local.common_tags, {
    Environment = "prod"
    DataClass   = "confidential"
  })
}

# --- Artifact signing key (asymmetric) --------------------------------------
module "artifact_signing" {
  source = "../../modules/kms-key"

  alias       = "prod/signing/artifact-sign"
  description = "Build artifact signing key"
  key_spec    = "ECC_NIST_P384"
  key_usage   = "SIGN_VERIFY"

  enable_rotation        = false   # not supported for asymmetric keys
  key_administrator_arns = local.key_admins
  key_user_arns          = ["arn:aws:iam::111122223333:role/github-actions-signing"]

  tags = merge(local.common_tags, {
    Environment = "prod"
    DataClass   = "internal"
  })
}

# --- Token integrity MAC key ------------------------------------------------
module "token_mac" {
  source = "../../modules/kms-key"

  alias       = "prod/integrity/token-mac"
  description = "Session token MAC key"
  key_spec    = "HMAC_256"
  key_usage   = "GENERATE_VERIFY_MAC"

  enable_rotation         = false
  key_administrator_arns  = local.key_admins
  cross_account_user_arns = [local.workload_root]

  tags = merge(local.common_tags, {
    Environment = "prod"
    DataClass   = "confidential"
  })
}
```

### `environments/security-prod/outputs.tf`

Export the ARNs so workload stacks can consume them via `terraform_remote_state`
or SSM Parameter Store.

```hcl
output "key_arns" {
  description = "Map of alias -> key ARN for all managed keys."
  value = {
    s3_general       = module.s3_general.key_arn
    ebs_default      = module.ebs_default.key_arn
    artifact_signing = module.artifact_signing.key_arn
    token_mac        = module.token_mac.key_arn
  }
}

# Publish to SSM so workload accounts can read them without remote state access
resource "aws_ssm_parameter" "key_arns" {
  for_each = {
    "s3-general"  = module.s3_general.key_arn
    "ebs-default" = module.ebs_default.key_arn
    "token-mac"   = module.token_mac.key_arn
  }

  name  = "/keymgmt/prod/${each.key}/arn"
  type  = "String"
  value = each.value
  tier  = "Standard"
}
```

## Plan and apply

```bash
cd environments/security-prod

terraform fmt -recursive -check
terraform validate
terraform plan -out=keys.tfplan
```

```text
Terraform used the selected providers to generate the following execution plan.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # module.s3_general.aws_kms_key.this will be created
  + resource "aws_kms_key" "this" {
      + arn                                = (known after apply)
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + deletion_window_in_days            = 30
      + enable_key_rotation                = true
      + rotation_period_in_days            = 365
      + description                        = "Prod platform key for general S3 object encryption"
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = false
      + policy                             = (known after apply)
      ...
    }

  # module.s3_general.aws_kms_alias.this will be created
  + resource "aws_kms_alias" "this" {
      + name          = "alias/prod/platform/s3-general"
      ...
    }

Plan: 10 to add, 0 to change, 0 to destroy.
```

Review the plan — specifically the rendered key policy — then apply:

```bash
terraform show -json keys.tfplan \
  | jq -r '.planned_values.root_module.child_modules[]
           | select(.address=="module.s3_general")
           | .resources[] | select(.type=="aws_kms_key") | .values.policy' \
  | jq .

terraform apply keys.tfplan
```

{: .tip }
> **Always render the policy from the plan before applying.** The
> `aws_iam_policy_document` data source composes statements dynamically; a
> mistake in a `for_each` produces a syntactically valid policy that grants the
> wrong thing. Reading the final JSON takes ten seconds and catches it.

## Importing an existing key

Keys created in the Console or by the CLI can be brought under Terraform
management without recreating them. Terraform 1.5+ supports declarative
`import` blocks, which are reviewable in a PR — prefer them over `terraform import`.

```hcl
# environments/security-prod/imports.tf  (delete after the first apply)
import {
  to = module.s3_general.aws_kms_key.this
  id = "1234abcd-12ab-34cd-56ef-1234567890ab"
}

import {
  to = module.s3_general.aws_kms_alias.this
  id = "alias/prod/platform/s3-general"
}
```

```bash
# Generate matching configuration to compare against what you wrote
terraform plan -generate-config-out=generated.tf

# Then a normal plan should show "0 to add, 0 to change, 0 to destroy"
terraform plan
```

The imperative equivalent, if you are on an older Terraform:

```bash
terraform import module.s3_general.aws_kms_key.this 1234abcd-12ab-34cd-56ef-1234567890ab
terraform import module.s3_general.aws_kms_alias.this alias/prod/platform/s3-general
```

{: .warning }
> After importing, the very first `terraform plan` frequently shows a diff on
> `policy` — because the hand-written policy and the module-generated policy
> differ in statement order, `Sid` values, or whitespace. **Read that diff
> carefully.** Applying it replaces your live key policy. Confirm the new policy
> is semantically equivalent or intentionally better before you accept it.

## Multi-Region keys in Terraform

```hcl
provider "aws" {
  alias  = "replica"
  region = "us-west-2"
}

module "rds_primary" {
  source = "../../modules/kms-key"

  alias        = "prod/data/rds-primary"
  description  = "Prod RDS storage encryption key (multi-Region primary)"
  multi_region = true

  key_administrator_arns  = local.key_admins
  cross_account_user_arns = [local.workload_root]

  tags = merge(local.common_tags, { Environment = "prod", DataClass = "restricted" })
}

resource "aws_kms_replica_key" "rds_primary_west" {
  provider = aws.replica

  description             = "Prod RDS storage encryption key (us-west-2 replica)"
  primary_key_arn         = module.rds_primary.key_arn
  deletion_window_in_days = 30
  policy                  = module.rds_primary.key_policy_json

  tags = merge(local.common_tags, { Environment = "prod", DataClass = "restricted" })
}

resource "aws_kms_alias" "rds_primary_west" {
  provider      = aws.replica
  name          = "alias/prod/data/rds-primary"
  target_key_id = aws_kms_replica_key.rds_primary_west.key_id
}
```

To make `module.rds_primary.key_policy_json` available, add this output to the
module:

```hcl
output "key_policy_json" {
  description = "The rendered key policy, for reuse on replica keys."
  value       = data.aws_iam_policy_document.key.json
}
```

{: .note }
> **A replica key has the same key material and the same key ID suffix as its
> primary**, so ciphertext produced in one Region decrypts in the other. It has
> its own, independently editable key policy, its own tags, and its own
> CloudTrail entries. Rotation is managed on the primary and propagates. Full
> detail in [Multi-Region Keys]({% link docs/multi-region-keys.md %}).

---

[Next: 5.4 CloudFormation]({% link docs/kms-cloudformation.md %}){: .btn .btn-primary }
