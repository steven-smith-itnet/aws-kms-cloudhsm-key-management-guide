---
title: Sources & References
nav_order: 18
---

# Sources &amp; References
{: .no_toc }

Official documentation for every service and claim in this guide. Verify against
these before running anything in production — cloud APIs and pricing change
frequently, and this guide is a walkthrough, not an authority.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## AWS KMS

| Topic | Link |
|:--|:--|
| Developer Guide | [docs.aws.amazon.com/kms/latest/developerguide/](https://docs.aws.amazon.com/kms/latest/developerguide/) |
| Cryptographic details (whitepaper) | [docs.aws.amazon.com/kms/latest/cryptographic-details/](https://docs.aws.amazon.com/kms/latest/cryptographic-details/) |
| API reference | [docs.aws.amazon.com/kms/latest/APIReference/](https://docs.aws.amazon.com/kms/latest/APIReference/) |
| Key policies | [Key policies in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html) |
| Condition keys | [AWS KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/policy-conditions.html) |
| Grants | [Grants in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html) |
| Key rotation | [Rotating AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html) |
| Importing key material | [Importing key material](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html) |
| Multi-Region keys | [Multi-Region keys in AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html) |
| Custom key stores | [Custom key stores](https://docs.aws.amazon.com/kms/latest/developerguide/custom-key-store-overview.html) |
| External key stores | [External key stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html) |
| XKS proxy API specification | [AWS KMS External Key Store Proxy API](https://github.com/aws/aws-kms-xks-proxy) |
| Quotas | [Quotas](https://docs.aws.amazon.com/kms/latest/developerguide/limits.html) |
| Deleting keys | [Deleting AWS KMS keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html) |
| Pricing | [aws.amazon.com/kms/pricing/](https://aws.amazon.com/kms/pricing/) |

## AWS CloudHSM

| Topic | Link |
|:--|:--|
| User Guide | [docs.aws.amazon.com/cloudhsm/latest/userguide/](https://docs.aws.amazon.com/cloudhsm/latest/userguide/) |
| Getting started | [Getting started with AWS CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/getting-started.html) |
| Cluster initialization | [Initialize the cluster](https://docs.aws.amazon.com/cloudhsm/latest/userguide/initialize-cluster.html) |
| Client SDK 5 | [Install and configure Client SDK 5](https://docs.aws.amazon.com/cloudhsm/latest/userguide/install-and-configure-client-5.html) |
| CloudHSM CLI reference | [CloudHSM CLI](https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_cli-reference.html) |
| Managing users | [Managing HSM users](https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-hsm-users.html) |
| Quorum authentication | [Managing quorum (M of N)](https://docs.aws.amazon.com/cloudhsm/latest/userguide/quorum-authentication.html) |
| PKCS#11 library | [PKCS #11 library](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html) |
| JCE provider | [JCE provider](https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-library.html) |
| OpenSSL Dynamic Engine | [OpenSSL Dynamic Engine](https://docs.aws.amazon.com/cloudhsm/latest/userguide/openssl-library.html) |
| Backups | [Managing backups](https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-backups.html) |
| API reference | [AWS CloudHSM API Reference](https://docs.aws.amazon.com/cloudhsm/latest/APIReference/) |
| Pricing | [aws.amazon.com/cloudhsm/pricing/](https://aws.amazon.com/cloudhsm/pricing/) |

## Identity, organization, and governance

| Topic | Link |
|:--|:--|
| AWS Organizations | [docs.aws.amazon.com/organizations/](https://docs.aws.amazon.com/organizations/latest/userguide/) |
| Service control policies | [SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) |
| IAM Identity Center | [docs.aws.amazon.com/singlesignon/](https://docs.aws.amazon.com/singlesignon/latest/userguide/) |
| IAM policy evaluation logic | [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) |
| IAM Access Analyzer | [docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) |
| AWS Config | [docs.aws.amazon.com/config/](https://docs.aws.amazon.com/config/latest/developerguide/) |
| Config managed rules | [List of managed rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html) |
| CloudTrail | [docs.aws.amazon.com/awscloudtrail/](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/) |
| Security Hub | [docs.aws.amazon.com/securityhub/](https://docs.aws.amazon.com/securityhub/latest/userguide/) |
| Security Lake | [docs.aws.amazon.com/security-lake/](https://docs.aws.amazon.com/security-lake/latest/userguide/) |

## Automation and SDKs

| Topic | Link |
|:--|:--|
| AWS CLI v2 | [docs.aws.amazon.com/cli/latest/userguide/](https://docs.aws.amazon.com/cli/latest/userguide/) |
| AWS CLI KMS reference | [awscli.amazonaws.com/v2/documentation/api/latest/reference/kms/](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/kms/index.html) |
| boto3 KMS | [boto3.amazonaws.com/…/kms.html](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html) |
| AWS Encryption SDK | [docs.aws.amazon.com/encryption-sdk/](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/) |
| Data key caching | [Data key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html) |
| DynamoDB Encryption Client | [docs.aws.amazon.com/dynamodb-encryption-client/](https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/) |
| Terraform AWS provider — KMS | [registry.terraform.io/…/kms_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) |
| Terraform AWS provider — CloudHSM v2 | [registry.terraform.io/…/cloudhsm_v2_cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudhsm_v2_cluster) |
| CloudFormation KMS resources | [AWS::KMS resource type reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_KMS.html) |
| GitHub OIDC with AWS | [Configuring OpenID Connect in AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) |
| `aws-actions/configure-aws-credentials` | [github.com/aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials) |
| Open Policy Agent / Rego | [openpolicyagent.org/docs/latest/policy-language/](https://www.openpolicyagent.org/docs/latest/policy-language/) |
| Conftest | [conftest.dev](https://www.conftest.dev/) |
| Checkov | [checkov.io](https://www.checkov.io/) |

## Standards and compliance

| Standard | Link |
|:--|:--|
| NIST SP 800-53 Rev. 5 | [csrc.nist.gov/pubs/sp/800/53/r5/upd1/final](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) |
| NIST SP 800-57 Part 1 — Key Management | [csrc.nist.gov/pubs/sp/800/57/pt1/r5/final](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) |
| NIST SP 800-131A — Transitioning algorithms | [csrc.nist.gov/pubs/sp/800/131/a/r2/final](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) |
| FIPS 140-3 | [csrc.nist.gov/pubs/fips/140-3/final](https://csrc.nist.gov/pubs/fips/140-3/final) |
| CMVP validated modules search | [csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) |
| ISO/IEC 27001:2022 | [iso.org/standard/27001](https://www.iso.org/standard/27001) |
| PCI DSS v4.0 | [pcisecuritystandards.org](https://www.pcisecuritystandards.org/document_library/) |
| SOC 2 Trust Services Criteria | [aicpa-cima.com](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) |
| CIS AWS Foundations Benchmark | [cisecurity.org/benchmark/amazon_web_services](https://www.cisecurity.org/benchmark/amazon_web_services) |
| AWS FIPS compliance | [aws.amazon.com/compliance/fips/](https://aws.amazon.com/compliance/fips/) |
| AWS Shared Responsibility Model | [aws.amazon.com/compliance/shared-responsibility-model/](https://aws.amazon.com/compliance/shared-responsibility-model/) |

## Companion guides

| Cloud | Guide |
|:--|:--|
| Azure | [Azure Key Vault &amp; Managed HSM Key Management Guide](https://steven-smith-itnet.github.io/azure-key-vault-managed-hsm-key-management-guide/) |
| Google Cloud | [Google Cloud KMS &amp; Cloud HSM Key Management Guide](https://steven-smith-itnet.github.io/gcp-cloud-kms-hsm-key-management-guide/) |

---

## About this guide

Prepared by [steven-smith-itnet](https://github.com/steven-smith-itnet) as an independent
technical walkthrough. It is not affiliated with, endorsed by, or reviewed by
Amazon Web Services.

Commands, API shapes, console navigation, and pricing reflect publicly documented
behavior at the time of writing. **Verify everything against current official
documentation before use in production.**

[View this guide on GitHub](https://github.com/steven-smith-itnet/aws-kms-cloudhsm-key-management-guide){: .btn }
