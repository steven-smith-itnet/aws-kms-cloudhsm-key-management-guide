---
title: 8. CloudHSM & HSM-Backed Tiers
nav_order: 9
has_children: true
---

# CloudHSM &amp; HSM-Backed Tiers
{: .no_toc }

**Phase 5 — HSM tier.** Single-tenant, FIPS 140-3 Level 3 hardware you control,
and the two ways to put KMS in front of it.
{: .fs-5 .fw-300 }

---

## What you are taking on

CloudHSM is not "KMS with better hardware." It is a different operating model,
and the responsibility shift is the main thing to understand before you start.

| Responsibility | AWS KMS | AWS CloudHSM |
|:--|:--|:--|
| HSM hardware and firmware | AWS | AWS |
| Cluster sizing and HA | AWS | **You** |
| Cryptographic user management | N/A (IAM) | **You** — CO/CU accounts inside the HSM |
| Password and quorum management | N/A | **You** |
| Backup retention policy | AWS | **You** (7–379 days) |
| Client software on your instances | N/A | **You** |
| Availability if you misconfigure it | AWS's problem | **Your problem** |
| Losing access to key material | Essentially impossible | **Entirely possible** |

{: .warning }
> **CloudHSM will let you destroy your keys permanently.** Lose the crypto-user
> password with no quorum recovery, delete the last HSM and all backups, or lose
> the trust anchor — and the key material is gone. AWS cannot recover it; that is
> what single-tenancy means. Everything in this section that looks like paperwork
> (ceremony logs, password escrow, backup verification) is the actual control.

## Which HSM-backed pattern

```mermaid
flowchart TD
    S{"What talks to the HSM?"}
    S -->|"AWS services:<br/>S3, EBS, RDS…"| CKS["<b>KMS custom key store</b><br/>KMS API in front,<br/>CloudHSM behind"]
    S -->|"Your application, using<br/>PKCS#11 / JCE / OpenSSL"| DIRECT["<b>Direct CloudHSM</b><br/>Client SDK 5 on your hosts"]
    S -->|"AWS services, but key material<br/>must stay OUTSIDE AWS"| XKS["<b>KMS external key store</b><br/>KMS API, your HSM,<br/>your proxy"]
    CKS --> BOTH["Both patterns can share<br/>one cluster — but the keys<br/>are different objects"]
    DIRECT --> BOTH
```

| Pattern | Application sees | Key material | Use for |
|:--|:--|:--|:--|
| **Custom key store** | The ordinary KMS API | In your CloudHSM cluster | S3/EBS/RDS encryption that must be single-tenant HSM-backed |
| **Direct CloudHSM** | PKCS#11, JCE, OpenSSL, CNG | In your CloudHSM cluster | Certificate authorities, code signing, payment HSM workloads, Oracle TDE, SSL offload |
| **External key store** | The ordinary KMS API | In *your* HSM, outside AWS | Hold-your-own-key and key-custody mandates |

## The build sequence

```mermaid
flowchart LR
    A["8.1<br/>Provision cluster<br/>+ first HSM"] --> B["8.2<br/>Trust anchor CA<br/>+ sign CSR<br/>+ initialize"]
    B --> C["8.3<br/>Activate<br/>+ create CO/CU users"]
    C --> D["8.4<br/>Client SDK 5<br/>PKCS#11 / JCE / OpenSSL"]
    C --> E["8.5<br/>KMS custom<br/>key store"]
    E --> F["8.6<br/>External key store<br/>(alternative design)"]
```

## Pages in this section

| Page | What it covers |
|:--|:--|
| [8.1 Provisioning]({% link docs/cloudhsm-provision.md %}) | VPC design, subnets, security groups, cluster and HSM creation |
| [8.2 Initialization Ceremony]({% link docs/cloudhsm-initialize.md %}) | The trust anchor CA, CSR signing, and `initialize-cluster` |
| [8.3 Users &amp; Keys]({% link docs/cloudhsm-users-cli.md %}) | Activation, CO/CU/AU roles, quorum, and key generation |
| [8.4 Application Integration]({% link docs/cloudhsm-apps.md %}) | PKCS#11, JCE, OpenSSL engine, Windows CNG/KSP |
| [8.5 KMS Custom Key Store]({% link docs/custom-key-store.md %}) | Putting the KMS API in front of your cluster |
| [8.6 External Key Store (XKS)]({% link docs/external-key-store.md %}) | Keeping key material entirely outside AWS |

## Cost reality check

CloudHSM is billed per HSM-hour, and a production cluster needs at least two.
Before you start, price it:

```bash
# List the HSM types available in your Region
aws cloudhsmv2 describe-clusters \
  --query 'Clusters[].{Id:ClusterId,Type:HsmType,State:State,HSMs:length(Hsms)}' \
  --output table

# Current on-demand pricing (check the live pricing page — this returns the
# authoritative value for your Region)
aws pricing get-products --region us-east-1 \
  --service-code AWSCloudHSM \
  --filters "Type=TERM_MATCH,Field=location,Value=US East (N. Virginia)" \
  --max-results 1 --query 'PriceList[0]' --output text | jq -r '.terms.OnDemand'
```

{: .important }
> A two-HSM cluster runs continuously — there is no "stop" state. Multiply the
> hourly rate by 730 hours by two HSMs, then add a third for the dev cluster you
> will inevitably need. That number, not the technical work, is usually what
> decides whether CloudHSM is the right answer. Compare it honestly against KMS
> at a few dollars per key per month before committing. See
> [Cost Model]({% link docs/cost.md %}).

---

[Next: 8.1 Provisioning]({% link docs/cloudhsm-provision.md %}){: .btn .btn-primary }
