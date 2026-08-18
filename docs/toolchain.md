---
title: 4. Toolchain Setup
nav_order: 5
---

# Toolchain Setup
{: .no_toc }

**Phase 2 — Foundation.** Install and configure every tool this guide uses, and
lay out the repository that will hold the infrastructure code.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## What you need

| Tool | Minimum version | Used for |
|:--|:--|:--|
| AWS CLI | v2.15+ | All CLI steps, SSO login, CloudHSM cluster management |
| Terraform | 1.6+ | Primary IaC path |
| Python | 3.9+ | boto3 SDK examples, envelope encryption |
| `jq` | 1.6+ | JSON parsing in shell examples |
| `openssl` | 3.0+ | CloudHSM trust anchor / CSR signing, BYOK wrapping |
| Git | 2.30+ | Repo + CI |
| Docker | 24+ | Optional — CloudHSM client testing, Conftest |
| CloudHSM CLI | 5.x | CloudHSM user and key management |
| Checkov / Conftest | latest | Policy-as-code scanning |

## Install the AWS CLI v2

{: .note }
> **v1 is not sufficient.** CloudHSM v2 commands, SSO login, and several KMS
> parameters used in this guide require CLI v2.

**Linux (x86_64):**

```bash
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
sudo /tmp/aws/install --update
aws --version
```

**macOS:**

```bash
curl -fsSL "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o /tmp/AWSCLIV2.pkg
sudo installer -pkg /tmp/AWSCLIV2.pkg -target /
aws --version
```

**Windows (PowerShell as Administrator):**

```powershell
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi /qn
aws --version
```

Expected output (version will differ):

```text
aws-cli/2.31.4 Python/3.13.7 Linux/6.8.0-generic exe/x86_64
```

## Configure SSO access

Do **not** create long-lived IAM access keys for humans. Configure SSO once and
let it issue short-lived credentials.

```bash
aws configure sso
```

The interactive prompts:

```text
SSO session name (Recommended): keymgmt
SSO start URL [None]: https://d-1234567890.awsapps.com/start
SSO region [None]: us-east-1
SSO registration scopes [sso:account:access]: (accept default)
```

A browser opens for authentication. Then:

```text
There are N AWS accounts available to you.
> Security, aws-root+security@yourcompany.com (111122223333)
Using the role name "KeyAdministrator"
CLI default client Region [None]: us-east-1
CLI default output format [None]: json
CLI profile name [KeyAdministrator-111122223333]: keyadmin
```

### Set up profiles for every role you switch between

Edit `~/.aws/config` directly — it is faster than re-running the wizard:

```ini
[sso-session keymgmt]
sso_start_url = https://d-1234567890.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile keyadmin]
sso_session = keymgmt
sso_account_id = 111122223333
sso_role_name = KeyAdministrator
region = us-east-1
output = json

[profile keyauditor]
sso_session = keymgmt
sso_account_id = 111122223333
sso_role_name = KeyAuditor
region = us-east-1
output = json

[profile prod]
sso_session = keymgmt
sso_account_id = 444455556666
sso_role_name = PowerUserAccess
region = us-east-1
output = json

[profile breakglass]
sso_session = keymgmt
sso_account_id = 111122223333
sso_role_name = BreakGlassAdmin
region = us-east-1
output = json
```

Log in and verify:

```bash
aws sso login --sso-session keymgmt

aws sts get-caller-identity --profile keyadmin
```

```json
{
    "UserId": "AROAEXAMPLEID:steven.smith@yourcompany.com",
    "Account": "111122223333",
    "Arn": "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_KeyAdministrator_abc123/steven.smith@yourcompany.com"
}
```

{: .tip }
> Export `AWS_PROFILE=keyadmin` in your shell instead of appending `--profile` to
> every command. The rest of this guide assumes you have done so; commands are
> shown without the flag for readability.

### Prove the separation of duties actually works

This is a five-second test that catches a misconfigured permission set before it
matters:

```bash
export AWS_PROFILE=keyadmin

# Should SUCCEED — key admins can describe keys
aws kms list-keys --max-items 1

# Should FAIL with AccessDeniedException — key admins must not decrypt
aws kms decrypt --ciphertext-blob fileb:///dev/null 2>&1 | head -2
```

Expected failure:

```text
An error occurred (AccessDeniedException) when calling the Decrypt operation:
User: arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_KeyAdministrator_abc123/... is not authorized
```

{: .important }
> If the `Decrypt` call fails with `ValidationException` or
> `InvalidCiphertextException` instead of `AccessDeniedException`, your deny is
> **not** working — the request got past authorization and failed on the payload.
> Go back to [Account Setup]({% link docs/account-setup.md %}) and fix the
> permission set before continuing.

## Install Terraform

```bash
# Linux (HashiCorp apt repo)
wget -O- https://apt.releases.hashicorp.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y terraform

terraform version
```

```bash
# macOS
brew tap hashicorp/tap && brew install hashicorp/tap/terraform
```

## Install Python and boto3

```bash
python3 -m venv ~/.venvs/kms
source ~/.venvs/kms/bin/activate

pip install --upgrade pip
pip install "boto3>=1.34" "botocore>=1.34" cryptography aws-encryption-sdk

python -c "import boto3; print('boto3', boto3.__version__)"
```

| Package | Why |
|:--|:--|
| `boto3` | The AWS SDK — all KMS API calls |
| `cryptography` | Local AES-GCM for the envelope encryption examples |
| `aws-encryption-sdk` | Production-grade client-side encryption with data key caching |

## Install the supporting utilities

```bash
# Linux
sudo apt-get install -y jq openssl git unzip

# Policy-as-code scanners
pip install checkov
curl -fsSL https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz \
  | sudo tar xz -C /usr/local/bin conftest

checkov --version && conftest --version
```

## Repository layout

Create the repository that will hold everything. This layout separates the
*definition* of keys from the *environments* that consume them, and keeps the
CloudHSM ceremony material out of version control.

```text
aws-key-management/
├── .github/
│   └── workflows/
│       ├── terraform-plan.yml        # PR: fmt, validate, checkov, plan
│       ├── terraform-apply.yml       # main: apply with OIDC
│       └── drift-detect.yml          # nightly: plan -detailed-exitcode
├── modules/
│   ├── kms-key/                      # reusable CMK module
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── README.md
│   ├── kms-multi-region-key/
│   └── cloudhsm-cluster/
├── environments/
│   ├── security-prod/                # the account that owns the keys
│   │   ├── backend.tf
│   │   ├── providers.tf
│   │   ├── keys.tf
│   │   ├── cloudhsm.tf
│   │   └── terraform.tfvars
│   ├── security-dev/
│   └── workload-prod/                # consumers: buckets, volumes, DBs
├── cloudformation/
│   ├── kms-key.yaml                  # the same key, as CFN
│   └── kms-key-params-prod.json
├── policies/
│   ├── scp/
│   │   ├── deny-key-deletion.json
│   │   └── require-kms-encryption.json
│   ├── opa/
│   │   └── kms.rego                  # Conftest rules for the Terraform plan
│   └── config-rules/
│       └── custom-cmk-rotation.py
├── scripts/
│   ├── envelope_encrypt.py
│   ├── key_inventory.py              # audit evidence export
│   ├── rotate_report.sh
│   └── cloudhsm/
│       ├── 01-create-cluster.sh
│       ├── 02-sign-csr.sh            # runs on the OFFLINE CA host
│       └── 03-initialize.sh
├── docs/
│   └── key-inventory.md              # generated; the auditor-facing register
├── .gitignore
└── README.md
```

```bash
mkdir -p aws-key-management/{.github/workflows,modules/{kms-key,kms-multi-region-key,cloudhsm-cluster},environments/{security-prod,security-dev,workload-prod},cloudformation,policies/{scp,opa,config-rules},scripts/cloudhsm,docs}
cd aws-key-management && git init -b main
```

### The `.gitignore` that keeps you out of trouble

```bash
cat > .gitignore <<'GITIGNORE'
# Terraform
.terraform/
*.tfstate
*.tfstate.*
*.tfplan
crash.log
.terraform.lock.hcl.bak

# NEVER COMMIT — CloudHSM ceremony material
*.pem
*.key
customerCA.crt
customerCA.key
*_ClusterCsr.csr
*_CustomerHsmCertificate.crt
security-domain/
*.byok
*.blob

# Credentials
.env
*.tfvars.secret
credentials
GITIGNORE
```

{: .warning }
> **`customerCA.key` is the private key of the CA that anchors your entire
> CloudHSM cluster.** Anyone holding it can issue a certificate that impersonates
> your HSMs to your own client software. It belongs on an offline host or in an
> HSM — never in Git, never in S3, never in a CI secret. The `.gitignore` above
> is a backstop, not a control.

## Terraform backend bootstrap

State for key infrastructure is itself sensitive: it contains key ARNs, policy
documents, and (for some resources) attributes you would rather not leak. Encrypt
it with a CMK, version it, and lock it.

```bash
export AWS_PROFILE=keyadmin
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="tfstate-keymgmt-${ACCOUNT_ID}"

# 1. State bucket
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1
aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. A bootstrap CMK to encrypt the state (chicken-and-egg: this one key is
#    created by hand; every key after it is created by Terraform).
STATE_KEY_ARN=$(aws kms create-key \
  --description "Terraform state encryption - key management repo" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --tags TagKey=Environment,TagValue=prod TagKey=ManagedBy,TagValue=bootstrap \
  --query 'KeyMetadata.Arn' --output text)

aws kms create-alias --alias-name alias/prod/platform/tfstate \
  --target-key-id "$STATE_KEY_ARN"
aws kms enable-key-rotation --key-id "$STATE_KEY_ARN"

# 3. Default-encrypt the bucket with it
aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration "{
    \"Rules\": [{
      \"ApplyServerSideEncryptionByDefault\": {
        \"SSEAlgorithm\": \"aws:kms\",
        \"KMSMasterKeyID\": \"$STATE_KEY_ARN\"
      },
      \"BucketKeyEnabled\": true
    }]
  }"

echo "State bucket: $BUCKET"
echo "State key:    $STATE_KEY_ARN"
```

{: .tip }
> `BucketKeyEnabled: true` is not optional at scale. It makes S3 request one data
> key per bucket per short interval instead of one per object, cutting KMS
> request charges for a high-object-count bucket by orders of magnitude. See
> [Cost Model]({% link docs/cost.md %}).

Now write the backend config (Terraform 1.6+ supports S3-native state locking
with `use_lockfile`, removing the old DynamoDB table requirement):

```hcl
# environments/security-prod/backend.tf
terraform {
  required_version = ">= 1.6"

  backend "s3" {
    bucket       = "tfstate-keymgmt-111122223333"
    key          = "security-prod/keys.tfstate"
    region       = "us-east-1"
    encrypt      = true
    kms_key_id   = "alias/prod/platform/tfstate"
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}
```

```hcl
# environments/security-prod/providers.tf
provider "aws" {
  region  = var.region
  profile = var.profile   # omit in CI — OIDC supplies credentials

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Repository  = "aws-key-management"
      Environment = var.environment
    }
  }
}
```

Initialize:

```bash
cd environments/security-prod
terraform init
```

```text
Initializing the backend...
Successfully configured the backend "s3"!
Initializing provider plugins...
- Installing hashicorp/aws v5.62.0...
Terraform has been successfully initialized!
```

## Toolchain checklist

| # | Check | Command |
|:--|:--|:--|
| 1 | AWS CLI v2 installed | `aws --version` |
| 2 | SSO login works | `aws sts get-caller-identity` |
| 3 | Key admin **cannot** decrypt | see the SoD test above |
| 4 | Terraform installed | `terraform version` |
| 5 | boto3 importable | `python -c "import boto3"` |
| 6 | Repo scaffolded with `.gitignore` | `git status` |
| 7 | State bucket encrypted with a CMK | `aws s3api get-bucket-encryption --bucket "$BUCKET"` |
| 8 | `terraform init` succeeds | `terraform init` |

---

[Next: Creating Keys]({% link docs/kms.md %}){: .btn .btn-primary }
