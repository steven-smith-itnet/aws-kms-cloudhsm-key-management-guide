---
title: 5.5 Python SDK (boto3)
parent: 5. Creating Keys
nav_order: 5
---

# Creating and managing keys with boto3
{: .no_toc }

Use the SDK when keys are created *by an application* — per-tenant keys, keys
minted during onboarding — and to produce the audit evidence a spreadsheet-driven
compliance process actually consumes.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## A production-shaped key provisioner

`scripts/kms_provision.py`

```python
#!/usr/bin/env python3
"""Idempotent KMS customer managed key provisioning.

Creates a key only when its alias does not already exist, so the script is safe
to re-run from a pipeline. Handles the key-spec/key-usage/rotation interactions
that trip up hand-rolled scripts.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger("kms-provision")

# Retries matter: KMS is a shared, rate-limited service and ThrottlingException
# is normal under load, not an error condition.
BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="keymgmt-guide/1.0",
)

USAGE_FOR_SPEC = {
    "SYMMETRIC_DEFAULT": "ENCRYPT_DECRYPT",
    "RSA_2048": "ENCRYPT_DECRYPT",
    "RSA_3072": "ENCRYPT_DECRYPT",
    "RSA_4096": "ENCRYPT_DECRYPT",
    "ECC_NIST_P256": "SIGN_VERIFY",
    "ECC_NIST_P384": "SIGN_VERIFY",
    "ECC_NIST_P521": "SIGN_VERIFY",
    "ECC_SECG_P256K1": "SIGN_VERIFY",
    "HMAC_224": "GENERATE_VERIFY_MAC",
    "HMAC_256": "GENERATE_VERIFY_MAC",
    "HMAC_384": "GENERATE_VERIFY_MAC",
    "HMAC_512": "GENERATE_VERIFY_MAC",
}


@dataclass
class KeySpecification:
    alias: str                       # without the 'alias/' prefix
    description: str
    key_spec: str = "SYMMETRIC_DEFAULT"
    multi_region: bool = False
    rotation_days: int = 365
    deletion_window_days: int = 30
    policy: dict[str, Any] | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def full_alias(self) -> str:
        return f"alias/{self.alias}"

    @property
    def key_usage(self) -> str:
        try:
            return USAGE_FOR_SPEC[self.key_spec]
        except KeyError:
            raise ValueError(f"Unsupported key_spec: {self.key_spec}") from None

    @property
    def rotation_supported(self) -> bool:
        # Automatic rotation applies only to symmetric, KMS-origin keys.
        return self.key_spec == "SYMMETRIC_DEFAULT"


class KeyProvisioner:
    def __init__(self, region: str, profile: str | None = None) -> None:
        session = boto3.Session(profile_name=profile, region_name=region)
        self.kms = session.client("kms", config=BOTO_CONFIG)
        self.sts = session.client("sts", config=BOTO_CONFIG)
        self.region = region
        self.account_id = self.sts.get_caller_identity()["Account"]

    # -- idempotency ------------------------------------------------------
    def find_key_by_alias(self, full_alias: str) -> str | None:
        """Return the key ARN behind an alias, or None. Does not raise on 404."""
        try:
            meta = self.kms.describe_key(KeyId=full_alias)["KeyMetadata"]
            return meta["Arn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return None
            raise

    # -- policy -----------------------------------------------------------
    def default_policy(self, admin_arns: list[str], user_arns: list[str]) -> dict:
        statements: list[dict] = [
            {
                "Sid": "EnableIAMUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{self.account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ]
        if admin_arns:
            statements.append({
                "Sid": "AllowKeyAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": admin_arns},
                "Action": [
                    "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
                    "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
                    "kms:Get*", "kms:TagResource", "kms:UntagResource",
                    "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
                ],
                "Resource": "*",
            })
        if user_arns:
            statements.append({
                "Sid": "AllowKeyUse",
                "Effect": "Allow",
                "Principal": {"AWS": user_arns},
                "Action": [
                    "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
                    "kms:GenerateDataKey*", "kms:DescribeKey",
                    "kms:Sign", "kms:Verify", "kms:GenerateMac", "kms:VerifyMac",
                ],
                "Resource": "*",
            })
        return {"Version": "2012-10-17", "Id": "key-policy", "Statement": statements}

    # -- create -----------------------------------------------------------
    def provision(self, spec: KeySpecification) -> dict[str, Any]:
        existing = self.find_key_by_alias(spec.full_alias)
        if existing:
            log.info("%s already exists -> %s", spec.full_alias, existing)
            return self.describe(existing)

        params: dict[str, Any] = {
            "Description": spec.description,
            "KeySpec": spec.key_spec,
            "KeyUsage": spec.key_usage,
            "Origin": "AWS_KMS",
            "MultiRegion": spec.multi_region,
            "Tags": [
                {"TagKey": k, "TagValue": v}
                for k, v in {**spec.tags, "Alias": spec.alias,
                             "ManagedBy": "boto3"}.items()
            ],
        }
        if spec.policy:
            params["Policy"] = json.dumps(spec.policy)

        log.info("Creating key for %s (spec=%s)", spec.full_alias, spec.key_spec)
        meta = self.kms.create_key(**params)["KeyMetadata"]
        key_id = meta["KeyId"]

        self.kms.create_alias(AliasName=spec.full_alias, TargetKeyId=key_id)
        log.info("Aliased %s -> %s", spec.full_alias, key_id)

        if spec.rotation_supported:
            self.kms.enable_key_rotation(
                KeyId=key_id, RotationPeriodInDays=spec.rotation_days
            )
            log.info("Rotation enabled (%dd)", spec.rotation_days)
        else:
            log.info("Rotation not supported for %s — skipped", spec.key_spec)

        return self.describe(meta["Arn"])

    def describe(self, key_id: str) -> dict[str, Any]:
        meta = self.kms.describe_key(KeyId=key_id)["KeyMetadata"]
        try:
            rot = self.kms.get_key_rotation_status(KeyId=key_id)
        except ClientError:
            rot = {"KeyRotationEnabled": False}
        aliases = self.kms.list_aliases(KeyId=key_id).get("Aliases", [])
        return {
            "KeyId": meta["KeyId"],
            "Arn": meta["Arn"],
            "Aliases": [a["AliasName"] for a in aliases],
            "KeyState": meta["KeyState"],
            "KeySpec": meta["KeySpec"],
            "KeyUsage": meta["KeyUsage"],
            "Origin": meta["Origin"],
            "MultiRegion": meta.get("MultiRegion", False),
            "RotationEnabled": rot.get("KeyRotationEnabled", False),
            "RotationPeriodInDays": rot.get("RotationPeriodInDays"),
            "CreationDate": meta["CreationDate"].isoformat(),
        }


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision a KMS customer managed key")
    ap.add_argument("alias", help="Alias suffix, e.g. prod/platform/s3-general")
    ap.add_argument("description")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--key-spec", default="SYMMETRIC_DEFAULT",
                    choices=sorted(USAGE_FOR_SPEC))
    ap.add_argument("--multi-region", action="store_true")
    ap.add_argument("--rotation-days", type=int, default=365)
    ap.add_argument("--admin-arn", action="append", default=[])
    ap.add_argument("--user-arn", action="append", default=[])
    ap.add_argument("--tag", action="append", default=[],
                    metavar="KEY=VALUE")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")

    tags = dict(t.split("=", 1) for t in args.tag)
    prov = KeyProvisioner(region=args.region, profile=args.profile)

    spec = KeySpecification(
        alias=args.alias,
        description=args.description,
        key_spec=args.key_spec,
        multi_region=args.multi_region,
        rotation_days=args.rotation_days,
        policy=prov.default_policy(args.admin_arn, args.user_arn)
        if (args.admin_arn or args.user_arn) else None,
        tags=tags,
    )

    try:
        result = prov.provision(spec)
    except ClientError as exc:
        log.error("KMS error: %s", exc.response["Error"]["Message"])
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run it:

```bash
python scripts/kms_provision.py \
  prod/platform/s3-general \
  "Prod platform key for general S3 object encryption" \
  --region us-east-1 \
  --admin-arn arn:aws:iam::111122223333:role/KeyAdministrator \
  --tag Environment=prod --tag DataClass=confidential
```

```json
{
  "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
  "Arn": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "Aliases": ["alias/prod/platform/s3-general"],
  "KeyState": "Enabled",
  "KeySpec": "SYMMETRIC_DEFAULT",
  "KeyUsage": "ENCRYPT_DECRYPT",
  "Origin": "AWS_KMS",
  "MultiRegion": false,
  "RotationEnabled": true,
  "RotationPeriodInDays": 365,
  "CreationDate": "2026-08-18T18:22:31.123000+00:00"
}
```

{: .tip }
> **`retries={"mode": "adaptive"}` is not optional at scale.** KMS enforces a
> per-Region request-rate quota shared across every principal in the account. A
> Lambda fan-out that calls `Decrypt` 5,000 times in a second will get
> `ThrottlingException`, and adaptive mode is what turns that from an outage into
> a slowdown. The other half of the answer is data key caching — see
> [Envelope Encryption]({% link docs/envelope-encryption.md %}).

## The audit evidence exporter

This is the artifact an auditor asks for: every customer managed key, its
rotation state, its age, its policy principals, and whether anything is
non-compliant with your own standard.

`scripts/key_inventory.py`

```python
#!/usr/bin/env python3
"""Export a KMS key inventory across Regions as JSON and CSV audit evidence."""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Your organization's standard — findings are raised against these.
MAX_KEY_AGE_DAYS = 1095            # 3 years without rotation is a finding
REQUIRED_TAGS = {"Environment", "DataClass", "Owner", "ManagedBy"}


def regions(session) -> list[str]:
    return session.client("ec2", region_name="us-east-1") \
        .describe_regions(AllRegions=False)["Regions"]


def collect(session, region: str) -> list[dict]:
    kms = session.client("kms", region_name=region)
    rows: list[dict] = []
    now = datetime.now(timezone.utc)

    for page in kms.get_paginator("list_keys").paginate():
        for entry in page["Keys"]:
            key_id = entry["KeyId"]
            try:
                meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue                      # AWS-owned keys we cannot read
            if meta["KeyManager"] != "CUSTOMER":
                continue                      # skip AWS managed keys

            try:
                rot = kms.get_key_rotation_status(KeyId=key_id)
            except ClientError:
                rot = {}

            try:
                tags = {t["TagKey"]: t["TagValue"]
                        for t in kms.list_resource_tags(KeyId=key_id)["Tags"]}
            except ClientError:
                tags = {}

            try:
                policy = json.loads(kms.get_key_policy(
                    KeyId=key_id, PolicyName="default")["Policy"])
                principals = sorted({
                    p
                    for st in policy.get("Statement", [])
                    for p in _as_list(st.get("Principal", {}).get("AWS", []))
                })
            except ClientError:
                principals = []

            aliases = [a["AliasName"] for a in
                       kms.list_aliases(KeyId=key_id).get("Aliases", [])]
            age_days = (now - meta["CreationDate"]).days

            findings = []
            if meta["KeySpec"] == "SYMMETRIC_DEFAULT" \
                    and not rot.get("KeyRotationEnabled"):
                findings.append("ROTATION_DISABLED")
            if age_days > MAX_KEY_AGE_DAYS and not rot.get("KeyRotationEnabled"):
                findings.append("KEY_AGE_EXCEEDED")
            if missing := REQUIRED_TAGS - set(tags):
                findings.append(f"MISSING_TAGS:{'|'.join(sorted(missing))}")
            if meta["KeyState"] == "PendingDeletion":
                findings.append("PENDING_DELETION")
            if any(p.endswith(":root") and not p.split(":")[4] ==
                   meta["AWSAccountId"] for p in principals):
                findings.append("CROSS_ACCOUNT_ROOT_PRINCIPAL")

            rows.append({
                "Region": region,
                "KeyId": key_id,
                "Arn": meta["Arn"],
                "Aliases": ";".join(aliases) or "<none>",
                "Description": meta.get("Description", ""),
                "KeyState": meta["KeyState"],
                "KeySpec": meta["KeySpec"],
                "KeyUsage": meta["KeyUsage"],
                "Origin": meta["Origin"],
                "MultiRegion": meta.get("MultiRegion", False),
                "CustomKeyStoreId": meta.get("CustomKeyStoreId", ""),
                "RotationEnabled": rot.get("KeyRotationEnabled", False),
                "RotationPeriodInDays": rot.get("RotationPeriodInDays", ""),
                "NextRotationDate": str(rot.get("NextRotationDate", "")),
                "CreationDate": meta["CreationDate"].isoformat(),
                "AgeDays": age_days,
                "Environment": tags.get("Environment", ""),
                "DataClass": tags.get("DataClass", ""),
                "Owner": tags.get("Owner", ""),
                "ManagedBy": tags.get("ManagedBy", ""),
                "PolicyPrincipals": ";".join(principals),
                "Findings": ";".join(findings) or "NONE",
            })
    return rows


def _as_list(v):
    return v if isinstance(v, list) else [v] if v else []


def main() -> int:
    session = boto3.Session()
    target_regions = sys.argv[1:] or ["us-east-1", "us-west-2", "eu-west-1"]

    all_rows: list[dict] = []
    for r in target_regions:
        print(f"Scanning {r} ...", file=sys.stderr)
        all_rows.extend(collect(session, r))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    with open(f"kms-inventory-{stamp}.json", "w") as fh:
        json.dump(all_rows, fh, indent=2, default=str)

    if all_rows:
        with open(f"kms-inventory-{stamp}.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(all_rows[0]))
            w.writeheader()
            w.writerows(all_rows)

    total = len(all_rows)
    flagged = sum(1 for r in all_rows if r["Findings"] != "NONE")
    print(f"\n{total} customer managed keys across {len(target_regions)} Regions")
    print(f"{flagged} with findings, {total - flagged} clean")
    for row in all_rows:
        if row["Findings"] != "NONE":
            print(f"  [{row['Region']}] {row['Aliases']:<40} {row['Findings']}")

    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```

```bash
python scripts/key_inventory.py us-east-1 us-west-2
```

```text
Scanning us-east-1 ...
Scanning us-west-2 ...

14 customer managed keys across 2 Regions
3 with findings, 11 clean
  [us-east-1] alias/dev/analytics/scratch              ROTATION_DISABLED;MISSING_TAGS:DataClass|Owner
  [us-east-1] alias/prod/signing/artifact-sign         MISSING_TAGS:DataClass
  [us-west-2] <none>                                   ROTATION_DISABLED;MISSING_TAGS:Environment|DataClass|Owner|ManagedBy
```

{: .note }
> The non-zero exit code on findings is deliberate — it makes this script usable
> as a CI gate or a scheduled job that pages someone. See
> [Policy as Code]({% link docs/policy-as-code.md %}) for wiring it into
> GitHub Actions and AWS Config.

## Error handling that matters

These four exceptions account for most real KMS failures. Handle them explicitly
rather than catching `ClientError` and hoping.

```python
from botocore.exceptions import ClientError

RETRYABLE = {"ThrottlingException", "KMSInternalException",
             "LimitExceededException"}

def decrypt_with_context(kms, blob: bytes, context: dict[str, str]) -> bytes:
    try:
        return kms.decrypt(CiphertextBlob=blob, EncryptionContext=context)["Plaintext"]

    except ClientError as exc:
        code = exc.response["Error"]["Code"]

        if code == "IncorrectKeyException":
            # The ciphertext was not produced by the key you specified.
            raise RuntimeError("Ciphertext belongs to a different KMS key") from exc

        if code == "InvalidCiphertextException":
            # Almost always a mismatched encryption context — not corruption.
            raise RuntimeError(
                f"Decrypt failed; check the encryption context matches exactly: {context}"
            ) from exc

        if code == "KMSInvalidStateException":
            # The key is disabled or pending deletion. This is an operational
            # incident, not a bug — page someone.
            raise RuntimeError("KMS key is disabled or pending deletion") from exc

        if code == "AccessDeniedException":
            # Evaluate BOTH the key policy and the caller's IAM policy.
            raise PermissionError("Not authorized to use this key") from exc

        if code in RETRYABLE:
            raise                      # let botocore's adaptive retry handle it

        raise
```

{: .warning }
> **`InvalidCiphertextException` is the single most misdiagnosed KMS error.** It
> almost never means the ciphertext is corrupt. It means the encryption context
> supplied at decrypt does not byte-for-byte match the one supplied at encrypt —
> including key order sensitivity in some SDK versions, and including a context
> that was present at encrypt and omitted at decrypt. Log the context on both
> sides before you go looking for storage corruption.

---

[Next: 6. Key Policies &amp; Access Control]({% link docs/kms-policies.md %}){: .btn .btn-primary }
