---
title: 14. Governance & Compliance
nav_order: 15
---

# Governance &amp; Compliance Mapping
{: .no_toc }

**Phase 7 — Govern.** The FIPS posture, the control mappings, and the evidence
that turns a working system into a passed audit.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## FIPS 140 posture

| Service | Validation | Notes |
|:--|:--|:--|
| AWS KMS HSMs | FIPS 140-3 **Level 3** | The HSMs backing KMS in AWS commercial Regions |
| AWS CloudHSM `hsm2m.medium` | FIPS 140-3 **Level 3** | In `FIPS` cluster mode |
| AWS CloudHSM `hsm1.medium` | FIPS 140-2 **Level 3** | Previous generation |
| CloudHSM `NON_FIPS` mode | **Not validated** | Broader algorithm set, no FIPS claim |
| KMS FIPS API endpoints | FIPS 140-3 validated modules for the TLS termination | `kms-fips.<region>.amazonaws.com` |

{: .important }
> **Validation status and certificate numbers change.** Before writing a FIPS
> claim into a SOC 2 description, a FedRAMP SSP, or a customer questionnaire,
> verify the current certificate on the
> [NIST Cryptographic Module Validation Program search](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
> and on
> [AWS's FIPS compliance page](https://aws.amazon.com/compliance/fips/). Cite the
> certificate number, not a marketing page.

### Using FIPS endpoints

```bash
# Explicitly target the FIPS endpoint
aws kms list-keys --endpoint-url https://kms-fips.us-east-1.amazonaws.com

# Or make every SDK call use FIPS endpoints where available
export AWS_USE_FIPS_ENDPOINT=true
aws kms list-keys

# In boto3
python - <<'PY'
import boto3
from botocore.config import Config
kms = boto3.client("kms", config=Config(use_fips_endpoint=True))
print(kms.meta.endpoint_url)
PY
```

```text
https://kms-fips.us-east-1.amazonaws.com
```

```hcl
# Terraform: force FIPS endpoints provider-wide
provider "aws" {
  region             = "us-east-1"
  use_fips_endpoint  = true
}
```

{: .tip }
> Enforce it rather than trusting configuration. An SCP condition on
> `aws:SourceVpce`, combined with a VPC endpoint created against the FIPS
> endpoint service, is a preventative control. Documentation saying "we use FIPS
> endpoints" is not.

## Control mappings

### NIST SP 800-53 Rev. 5

| Control | Requirement | How this build satisfies it | Evidence |
|:--|:--|:--|:--|
| **SC-12** | Cryptographic key establishment and management | KMS/CloudHSM key generation in validated HSMs; documented hierarchy | [Architecture]({% link docs/architecture.md %}); `key_inventory.py` output |
| **SC-12(1)** | Availability of information in the event of key loss | Multi-Region keys, CloudHSM backups, escrowed trust anchor | [Backup &amp; DR]({% link docs/backup-dr.md %}); DR test record |
| **SC-12(2)** | Symmetric keys produced by a validated module | FIPS 140-3 L3 HSMs; `GenerateDataKey` | Key spec in `describe-key`; FIPS certificate |
| **SC-12(3)** | Asymmetric keys from an approved source | KMS asymmetric keys / CloudHSM key pairs | `describe-key` KeySpec |
| **SC-13** | Use of FIPS-validated cryptography | `SYMMETRIC_DEFAULT` = AES-256-GCM; FIPS endpoints | `AWS_USE_FIPS_ENDPOINT`; SCP |
| **SC-28** | Protection of information at rest | CMK-backed encryption on S3, EBS, RDS, DynamoDB, Secrets Manager | [Service Integrations]({% link docs/service-integrations.md %}); Config rules |
| **SC-28(1)** | Cryptographic protection at rest | Envelope encryption with per-object DEKs | [Envelope Encryption]({% link docs/envelope-encryption.md %}) |
| **AC-3** | Access enforcement | Key policies, IAM, grants, SCPs | `get-key-policy`; `list-grants` |
| **AC-5** | Separation of duties | `KeyAdministrator` denied cryptographic use; CO/CU split in the HSM | Permission set inline policy; `simulate-principal-policy` |
| **AC-6** | Least privilege | `kms:ViaService`, encryption-context conditions, scoped grants | Key policy documents |
| **AU-2 / AU-3** | Audit events and content | CloudTrail records every KMS call with context | CloudTrail; Athena queries |
| **AU-9** | Protection of audit information | Object Lock COMPLIANCE, log file validation | `validate-logs` output |
| **AU-12** | Audit record generation | Organization trail, all Regions | `get-trail-status` |
| **CM-3** | Configuration change control | Terraform + PR review + drift detection | PR history; drift issues |
| **CP-9** | System backup | CloudHSM backups; KMS config export | `describe-backups` |
| **IA-5** | Authenticator management | HSM passwords in Secrets Manager, rotated | Secret rotation config |
| **SI-4** | System monitoring | Canaries, EventBridge rules, anomaly queries | [Monitoring]({% link docs/monitoring.md %}) |

### ISO/IEC 27001:2022 Annex A

| Control | Title | How this build satisfies it |
|:--|:--|:--|
| **A.5.15** | Access control | Key policies + IAM + SCPs, reviewed quarterly |
| **A.5.16** | Identity management | IAM Identity Center with an external IdP; HSM users |
| **A.5.18** | Access rights | Quarterly key access review including grants |
| **A.5.23** | Information security for cloud services | Documented service-tier selection and shared-responsibility split |
| **A.8.10** | Information deletion | Key deletion procedure with a 30-day window and sign-off |
| **A.8.12** | Data leakage prevention | Encryption context binding; `kms:ViaService` |
| **A.8.24** | **Use of cryptography** | The cryptographic policy this entire guide implements |
| **A.8.15** | Logging | CloudTrail + CloudHSM audit log to a SIEM |
| **A.8.16** | Monitoring activities | Decrypt-anomaly detection; canaries |
| **A.8.32** | Change management | CI/CD with review, policy gate, and drift detection |

{: .note }
> **A.8.24 expects a documented cryptographic policy**, not just working
> encryption. It should state: approved algorithms and key lengths, key
> generation requirements, cryptoperiods per key purpose, roles and
> responsibilities for key management, and key destruction procedures. Sections
> [1]({% link docs/overview.md %}), [7.3]({% link docs/rotation.md %}), and
> [9]({% link docs/backup-dr.md %}) of this guide map to those clauses directly.

### SOC 2 Trust Services Criteria

| Criterion | Requirement | Implementation | Evidence artifact |
|:--|:--|:--|:--|
| **CC6.1** | Logical access controls over protected information | Key policies restrict use by principal, service, and context | Key policy export |
| **CC6.3** | Access based on roles and least privilege | Separated key admin / key user / auditor roles | Permission sets; SoD test output |
| **CC6.6** | Controls over external access | `aws:PrincipalOrgID` deny; Access Analyzer findings | Analyzer report |
| **CC6.7** | Restricted transmission and movement of data | TLS enforced by SCP; envelope encryption | SCP; canary results |
| **CC7.1** | Detection of configuration changes | Config rules, EventBridge, drift detection | Config compliance report |
| **CC7.2** | Monitoring for anomalies | Decrypt-volume anomaly detection | Athena/Splunk saved search |
| **CC7.3** | Evaluation of security events | On-call runbook with defined actions | [Monitoring runbook]({% link docs/monitoring.md %}#the-on-call-runbook) |
| **CC8.1** | Change management | PR review, CODEOWNERS, environment approval | PR history |
| **A1.2** | Environmental protections and recovery | Multi-Region keys, CloudHSM backup/restore | DR test record |

### PCI DSS v4.0

| Requirement | Text (summarized) | Implementation |
|:--|:--|:--|
| **3.5.1** | PAN rendered unreadable wherever stored | CMK-backed encryption, ideally CloudHSM custom key store |
| **3.6.1** | Key management procedures documented and implemented | This guide, adopted as your procedure |
| **3.6.1.1** | Key management procedures cover generation, distribution, storage, changes, retirement | Sections 5, 7.3, 7.4, 9 |
| **3.6.1.2** | Secret and private keys stored in the fewest possible locations | Keys never leave the HSM; envelope encryption limits DEK spread |
| **3.6.1.3** | Access to cryptographic keys restricted to the fewest custodians | Key policy naming explicit principals; HSM CO/CU split |
| **3.6.1.4** | Keys stored in a secure form | FIPS 140-3 L3 HSM; `extractable=false` |
| **3.7.1** | Key generation using strong cryptography | AES-256 / RSA-4096 / P-384 in a validated HSM |
| **3.7.2** | Secure key distribution | Keys are never distributed — operations occur in the HSM |
| **3.7.3** | Secure key storage | Same |
| **3.7.4** | Key changes at the end of the cryptoperiod | Rotation policy with a documented cryptoperiod |
| **3.7.5** | Retirement or replacement of keys | Manual rotation + re-encryption procedure |
| **3.7.6** | Manual clear-text key operations use split knowledge and dual control | BYOK and CloudHSM ceremonies with two custodians; quorum MofN |
| **3.7.7** | Unauthorized substitution of keys prevented | Trust anchor; `prevent_destroy`; SCP on deletion |
| **3.7.8** | Key custodians acknowledge their responsibilities | Ceremony log signatures |
| **10.2** | Audit logs for all access to cardholder data | CloudTrail + HSM audit log |

{: .warning }
> **PCI DSS 3.7.6 — split knowledge and dual control — is where most cloud key
> management programs fail an assessment.** It applies to *manual clear-text key
> operations*. If you never handle clear-text key material (pure KMS, keys
> generated in the HSM), the requirement is largely satisfied by design and you
> should say so explicitly. If you do BYOK, the two-custodian ceremony in
> [7.4]({% link docs/byok-import.md %}) is what satisfies it — and the ceremony
> log is the evidence. A ceremony performed by one person, however careful, does
> not.

## Evidence collection

The artifacts an assessor will ask for, and the command that produces each.

```bash
#!/usr/bin/env bash
# scripts/collect_audit_evidence.sh — one command, one evidence pack
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="audit-evidence-${STAMP}"
mkdir -p "$OUT"

echo "== 1. Key inventory with rotation status =="
python scripts/key_inventory.py us-east-1 us-west-2 \
  && mv kms-inventory-*.{json,csv} "$OUT/" 2>/dev/null || true

echo "== 2. Key policies =="
mkdir -p "$OUT/key-policies"
for KEY in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  MGR=$(aws kms describe-key --key-id "$KEY" \
    --query 'KeyMetadata.KeyManager' --output text 2>/dev/null) || continue
  [ "$MGR" = "CUSTOMER" ] || continue
  aws kms get-key-policy --key-id "$KEY" --policy-name default \
    --query Policy --output text | jq . > "$OUT/key-policies/${KEY}.json"
done

echo "== 3. Grants (the access-review blind spot) =="
for KEY in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  aws kms list-grants --key-id "$KEY" --output json 2>/dev/null \
    | jq --arg k "$KEY" '{key: $k, grants: .Grants}'
done | jq -s . > "$OUT/grants.json"

echo "== 4. Separation of duties proof =="
KEY_ADMIN=$(aws iam list-roles \
  --query "Roles[?starts_with(RoleName,'AWSReservedSSO_KeyAdministrator')].Arn" \
  --output text | head -1)
aws iam simulate-principal-policy \
  --policy-source-arn "$KEY_ADMIN" \
  --action-names kms:Decrypt kms:GenerateDataKey kms:CreateKey \
  --output json > "$OUT/sod-simulation.json"

echo "== 5. Config compliance =="
aws configservice describe-compliance-by-config-rule --output json \
  > "$OUT/config-compliance.json"

echo "== 6. CloudTrail integrity =="
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-management-trail" \
  --start-time "$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  > "$OUT/cloudtrail-validation.txt" 2>&1 || true

echo "== 7. CloudHSM cluster and backups =="
aws cloudhsmv2 describe-clusters --output json > "$OUT/cloudhsm-clusters.json"
aws cloudhsmv2 describe-backups --output json  > "$OUT/cloudhsm-backups.json"

echo "== 8. External access findings =="
ANALYZER=$(aws accessanalyzer list-analyzers \
  --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER" \
  --filter '{"resourceType":{"eq":["AWS::KMS::Key"]}}' \
  --output json > "$OUT/external-access-findings.json"

echo "== 9. SCPs in force =="
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output json \
  > "$OUT/scps.json"

tar czf "${OUT}.tar.gz" "$OUT" && rm -rf "$OUT"
sha256sum "${OUT}.tar.gz" | tee "${OUT}.tar.gz.sha256"
echo "Evidence pack: ${OUT}.tar.gz"
```

{: .tip }
> **Hash the evidence pack and record the hash separately** (a ticket, an email
> to the auditor, a signed commit). It lets you demonstrate later that the
> evidence provided in March is byte-identical to the evidence in your archive —
> which turns a pile of JSON into something with chain of custody.

## The key management policy document

Frameworks ask for a *policy*, not just a working system. Yours should state, at
minimum:

| Section | Content | Source in this guide |
|:--|:--|:--|
| Scope | Which systems, data classes, and Regions | [Overview]({% link docs/overview.md %}) |
| Approved algorithms | AES-256-GCM, RSA-4096, ECDSA P-384, HMAC-SHA-256 | [Overview]({% link docs/overview.md %}#key-specs-and-what-they-are-for) |
| Key generation | In FIPS 140-3 L3 validated HSMs only | [Architecture]({% link docs/architecture.md %}) |
| Key hierarchy | CMK → DEK envelope model | [Architecture]({% link docs/architecture.md %}) |
| Cryptoperiods | Per key purpose, with justification | [Rotation]({% link docs/rotation.md %}#rotation-policy--what-to-actually-write-down) |
| Roles | Key administrator, key user, key auditor, break-glass, HSM CO/CU | [Account Setup]({% link docs/account-setup.md %}) |
| Access review | Quarterly, including grants | [Key Policies]({% link docs/kms-policies.md %}#access-review-checklist) |
| Backup and recovery | What is backed up, by whom, tested how often | [Backup &amp; DR]({% link docs/backup-dr.md %}) |
| Destruction | 30-day window, checklist, sign-off | [Backup &amp; DR]({% link docs/backup-dr.md %}#the-deletion-checklist) |
| Incident response | Compromise → disable → rotate → re-encrypt | [Monitoring]({% link docs/monitoring.md %}#the-on-call-runbook) |
| Exceptions | How an exception is requested, approved, and expires | Your GRC process |

## Common audit findings, and how this build avoids them

| Finding | Root cause | Prevented by |
|:--|:--|:--|
| "Key rotation not enabled" | Nobody enabled it; nobody checked | OPA gate + Config rule + `rotate_report.sh` |
| "Key administrators can decrypt data" | Convenience during setup | Explicit IAM `Deny` on the permission set |
| "Cannot demonstrate who used key X" | No CloudTrail, or no encryption context | Organization trail + mandatory encryption context |
| "Grants not reviewed" | Grants are invisible in the Console's policy view | `list-grants` in the quarterly review and the evidence pack |
| "No documented cryptoperiod" | Rotation set to a default with no rationale | Written rotation policy with justification |
| "DR untested" | Nobody wanted to spend the day | Annual restore exercise with a recorded RTO |
| "Key deletion not controlled" | Anyone with `kms:*` can schedule deletion | SCP restricting deletion to break-glass |
| "Shadow keys outside IaC" | Console experiments that became production | EventBridge alert on non-pipeline `CreateKey` |
| "Ceremony performed by one person" | No second custodian available on the day | Two-custodian requirement in the ceremony procedure |

---

[Next: 15. Verification &amp; Runbook]({% link docs/verification.md %}){: .btn .btn-primary }
