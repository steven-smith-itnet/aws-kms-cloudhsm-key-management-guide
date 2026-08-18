---
title: 7. Key Operations
nav_order: 8
has_children: true
---

# Key Operations
{: .no_toc }

**Phase 4 — Operate.** Keys exist. Now put them to work and keep them healthy
through their whole lifecycle.
{: .fs-5 .fw-300 }

---

## The key lifecycle

```mermaid
stateDiagram-v2
    [*] --> Created: CreateKey
    Created --> Enabled: default
    Enabled --> Enabled: Rotate (new backing key,<br/>same key ID)
    Enabled --> Disabled: DisableKey
    Disabled --> Enabled: EnableKey
    Enabled --> PendingDeletion: ScheduleKeyDeletion
    Disabled --> PendingDeletion: ScheduleKeyDeletion
    PendingDeletion --> Enabled: CancelKeyDeletion
    PendingDeletion --> [*]: waiting period elapses<br/><b>IRREVERSIBLE</b>
    Enabled --> PendingImport: DeleteImportedKeyMaterial<br/>(EXTERNAL origin only)
    PendingImport --> Enabled: ImportKeyMaterial
```

Every state transition is a CloudTrail event, and the last one is permanent. The
pages in this section walk each operational concern in the order you will meet
it.

## Pages in this section

| Page | What it covers |
|:--|:--|
| [7.1 Envelope Encryption]({% link docs/envelope-encryption.md %}) | Data keys in application code, the AWS Encryption SDK, and key caching |
| [7.2 Service Integrations]({% link docs/service-integrations.md %}) | S3, EBS, RDS, Secrets Manager, DynamoDB, EFS, Lambda, SNS/SQS |
| [7.3 Rotation]({% link docs/rotation.md %}) | Automatic rotation, on-demand rotation, and manual key replacement |
| [7.4 Import &amp; BYOK]({% link docs/byok-import.md %}) | Importing your own key material, wrapping, and expiry |
| [7.5 Multi-Region Keys]({% link docs/multi-region-keys.md %}) | Replicas, cross-Region DR, and primary promotion |

Backup, recovery, and deletion are covered separately in
[9. Backup, DR &amp; Deletion]({% link docs/backup-dr.md %}), because they span
both KMS and CloudHSM.
