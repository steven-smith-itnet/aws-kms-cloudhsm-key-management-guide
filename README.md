# AWS KMS &amp; CloudHSM — Key Management Deployment Guide

A sequential, command-level guide to planning, deploying, automating, and
governing cryptographic key management on AWS — from an empty account through to
a governed, monitored, HSM-backed production service.

**📖 Read the guide: <https://smittystuff.github.io/aws-kms-cloudhsm-key-management-guide/>**

---

## What this covers

| Phase | Section | Contents |
|:--|:--|:--|
| 1 — Plan | Overview, Architecture | KMS vs. CloudHSM vs. custom key store vs. external key store; the key hierarchy and envelope-encryption model |
| 2 — Foundation | Account Setup, Toolchain | AWS Organizations, IAM Identity Center, separation-of-duties permission sets, CLI/Terraform/boto3, encrypted state backend |
| 3 — Build | Creating Keys, Key Policies | The same CMK six ways — Console, AWS CLI, Terraform, CloudFormation, Python SDK, CI/CD — plus key policies, grants, and SCPs |
| 4 — Operate | Key Operations, Backup &amp; DR | Envelope encryption, service integrations, rotation, BYOK import, multi-Region keys, backup/restore, and controlled deletion |
| 5 — HSM tier | CloudHSM | Cluster provisioning, the trust-anchor initialization ceremony, CO/CU users and quorum, PKCS#11/JCE/OpenSSL/CNG, KMS custom key store, external key store (XKS) |
| 6 — Observe | Logging &amp; SIEM, Monitoring | CloudTrail with Object Lock, Athena forensics, Splunk/Security Lake, canaries, alarms, and the on-call runbook |
| 7 — Govern | CI/CD, Policy as Code, Compliance | GitHub Actions with OIDC, OPA/Rego and Checkov gates, AWS Config rules, and NIST/ISO 27001/SOC 2/PCI DSS mappings |
| 8 — Verify | Verification, Cost | An executable acceptance-test suite, dependency mapping, incident runbooks, and the cost model |

**33 pages.** Every step is shown as a runnable command with expected output.
Steps that cannot be automated — account creation, key ceremonies, quorum
approvals — are called out explicitly so they can be planned into a change
window.

## Automation techniques demonstrated

- **AWS Console** — click-paths with every field explained
- **AWS CLI v2** — idempotent provisioning scripts, day-two operations, incident response
- **Terraform** — a reusable `kms-key` module, plan/apply gates, `import` blocks, multi-Region replicas
- **CloudFormation** — parameterized templates, change sets, StackSets for organization-wide rollout, drift detection
- **Python (boto3)** — a key provisioner, an audit-evidence inventory exporter, envelope encryption, the AWS Encryption SDK with data key caching
- **GitHub Actions** — OIDC federation (no stored credentials), plan/policy-gate/apply pipeline, nightly drift detection
- **Policy as code** — OPA/Rego on the Terraform plan, Checkov custom checks, SCPs, AWS Config rules and conformance packs
- **CloudHSM CLI &amp; Client SDK 5** — cluster ceremonies, user and key management, PKCS#11 / JCE / OpenSSL engine / Windows CNG

## Companion guides

This is one of three parallel guides sharing the same structure, so the same
concept can be compared across providers:

- **AWS KMS &amp; CloudHSM** — this repository
- [Azure Key Vault &amp; Managed HSM](https://github.com/SmittyStuff/azure-key-vault-managed-hsm-key-management-guide)
- [Google Cloud KMS &amp; Cloud HSM](https://github.com/SmittyStuff/gcp-cloud-kms-hsm-key-management-guide)

## Building locally

```bash
bundle install
bundle exec jekyll serve
# http://127.0.0.1:4000/aws-kms-cloudhsm-key-management-guide/
```

The published site is built and deployed by
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) on every push to
`main`.

## Disclaimer

An independent technical walkthrough based on publicly available AWS
documentation. Not affiliated with, endorsed by, or reviewed by Amazon Web
Services. Cloud APIs, console layouts, and pricing change frequently — verify
every step against current official documentation before use in production, and
validate all cost figures against current pricing pages.

## License

Documentation and code samples are provided as-is for educational and reference
purposes.
