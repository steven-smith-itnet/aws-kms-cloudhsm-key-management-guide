---
title: 11. Monitoring & Alerting
nav_order: 12
---

# Monitoring &amp; Alerting
{: .no_toc }

**Phase 6 — Observe.** What to watch, what to page on, and what to leave in a
weekly report.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## What to alert on

Alert design for key management has an unusual property: the highest-severity
events are **configuration changes**, not performance metrics. A key deleted at
2 a.m. is a bigger problem than a slow `Decrypt`.

| Signal | Severity | Why |
|:--|:--|:--|
| `ScheduleKeyDeletion` on any production key | **Page** | Potential permanent data loss |
| Custom key store leaves `CONNECTED` | **Page** | Every key in it is unusable now |
| CloudHSM cluster `DEGRADED` or an HSM unhealthy | **Page** | Redundancy lost |
| XKS proxy unreachable | **Page** | Same as a custom key store disconnect |
| `KMSInvalidStateException` rate spike | **Page** | A key is disabled or deleted mid-flight |
| `DisableKey` on a production key | **Page** | Immediate outage of dependent services |
| Decrypt volume anomaly (> 3σ over baseline) | **Page** | Possible bulk exfiltration |
| `PutKeyPolicy` on a production key | Ticket | Access model changed |
| `CreateGrant` outside CI/CD | Ticket | New access path |
| Throttling (`ThrottlingException`) rate rising | Ticket | Quota pressure ahead of an outage |
| Imported key material approaching `ValidTo` | Ticket, then page at 7 days | Scheduled outage if missed |
| Rotation disabled on a key that should have it | Weekly report | Compliance drift |
| Keys with no usage in 90 days | Monthly report | Retirement candidates |

## SNS topics and routing

```bash
CRITICAL=$(aws sns create-topic --name keymgmt-critical \
  --attributes '{"DisplayName":"KeyMgmt CRITICAL"}' \
  --query TopicArn --output text)
WARNING=$(aws sns create-topic --name keymgmt-warning \
  --query TopicArn --output text)

# Encrypt the topics — alarm payloads name your keys and principals
aws sns set-topic-attributes --topic-arn "$CRITICAL" \
  --attribute-name KmsMasterKeyId --attribute-value alias/prod/platform/s3-general

# Route: critical -> pager, warning -> ticket queue
aws sns subscribe --topic-arn "$CRITICAL" --protocol https \
  --notification-endpoint "https://events.pagerduty.com/integration/REPLACE/enqueue"
aws sns subscribe --topic-arn "$WARNING" --protocol email \
  --notification-endpoint "keymgmt-alerts@yourcompany.com"
```

## EventBridge rules for configuration changes

```bash
put_rule () {
  local NAME="$1" DESC="$2" PATTERN="$3" TARGET="$4"
  aws events put-rule --name "$NAME" --description "$DESC" --event-pattern "$PATTERN"
  aws events put-targets --rule "$NAME" --targets "Id=1,Arn=${TARGET}"
  echo "rule: $NAME"
}

# --- CRITICAL: destructive key operations ------------------------------------
put_rule "kms-destructive-operations" \
  "KMS key deletion, disable, or material removal" \
  '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["kms.amazonaws.com"],
      "eventName": ["ScheduleKeyDeletion","DisableKey","DisableKeyRotation",
                    "DeleteImportedKeyMaterial","DeleteCustomKeyStore",
                    "DisconnectCustomKeyStore"]
    }
  }' "$CRITICAL"

# --- CRITICAL: CloudHSM cluster and HSM health -------------------------------
put_rule "cloudhsm-state-change" \
  "CloudHSM cluster or HSM state change" \
  '{
    "source": ["aws.cloudhsm"],
    "detail-type": ["CloudHSM Cluster State Change","CloudHSM HSM State Change"]
  }' "$CRITICAL"

# --- WARNING: access model changes -------------------------------------------
put_rule "kms-access-changes" \
  "Key policy, grant, or alias changes" \
  '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["kms.amazonaws.com"],
      "eventName": ["PutKeyPolicy","CreateGrant","RevokeGrant",
                    "RetireGrant","UpdateAlias","ReplicateKey",
                    "UpdatePrimaryRegion","ImportKeyMaterial"]
    }
  }' "$WARNING"

# --- WARNING: keys created outside the pipeline ------------------------------
put_rule "kms-manual-key-creation" \
  "CreateKey by a principal that is not the CI/CD role" \
  '{
    "source": ["aws.kms"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["kms.amazonaws.com"],
      "eventName": ["CreateKey","CreateCustomKeyStore"],
      "userIdentity": {
        "sessionContext": {
          "sessionIssuer": {
            "arn": [{"anything-but": ["arn:aws:iam::111122223333:role/github-actions-keymgmt"]}]
          }
        }
      }
    }
  }' "$WARNING"
```

{: .tip }
> That last rule — "a key was created by something other than the pipeline" — is
> one of the highest-value alerts in the whole set. It catches shadow keys,
> console experiments that become production, and the early stages of an attacker
> establishing their own encryption. It costs nothing and fires rarely.

## CloudWatch alarms on KMS metrics

```bash
# --- Throttling: quota pressure before it becomes an outage ------------------
aws cloudwatch put-metric-alarm \
  --alarm-name "kms-throttling-elevated" \
  --alarm-description "KMS requests are being throttled" \
  --namespace AWS/Usage \
  --metric-name CallCount \
  --dimensions Name=Type,Value=API Name=Resource,Value=Decrypt \
               Name=Service,Value="AWS KMS" Name=Class,Value=None \
  --statistic Sum --period 300 --evaluation-periods 2 \
  --threshold 100000 --comparison-operator GreaterThanThreshold \
  --alarm-actions "$WARNING"

# --- Imported key material expiry --------------------------------------------
aws cloudwatch put-metric-alarm \
  --alarm-name "kms-imported-material-expiring" \
  --alarm-description "Imported key material expires within 30 days" \
  --namespace AWS/KMS \
  --metric-name SecondsUntilKeyMaterialExpiration \
  --dimensions Name=KeyId,Value=1234abcd-12ab-34cd-56ef-1234567890ab \
  --statistic Minimum --period 3600 --evaluation-periods 1 \
  --threshold 2592000 --comparison-operator LessThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$WARNING"

# --- Same key, 7 days out: page --------------------------------------------
aws cloudwatch put-metric-alarm \
  --alarm-name "kms-imported-material-expiring-critical" \
  --namespace AWS/KMS \
  --metric-name SecondsUntilKeyMaterialExpiration \
  --dimensions Name=KeyId,Value=1234abcd-12ab-34cd-56ef-1234567890ab \
  --statistic Minimum --period 3600 --evaluation-periods 1 \
  --threshold 604800 --comparison-operator LessThanThreshold \
  --alarm-actions "$CRITICAL"
```

### CloudHSM metrics

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "cloudhsm-unhealthy-hsm" \
  --alarm-description "One or more HSMs in the cluster are unhealthy" \
  --namespace AWS/CloudHSM \
  --metric-name HsmUnhealthy \
  --dimensions "Name=ClusterId,Value=${CLUSTER_ID}" \
  --statistic Maximum --period 300 --evaluation-periods 1 \
  --threshold 0 --comparison-operator GreaterThanThreshold \
  --alarm-actions "$CRITICAL"

aws cloudwatch put-metric-alarm \
  --alarm-name "cloudhsm-key-storage-high" \
  --alarm-description "HSM key storage above 80%" \
  --namespace AWS/CloudHSM \
  --metric-name HsmKeysSessionOccupied \
  --dimensions "Name=ClusterId,Value=${CLUSTER_ID}" \
  --statistic Maximum --period 300 --evaluation-periods 3 \
  --threshold 80 --comparison-operator GreaterThanThreshold \
  --alarm-actions "$WARNING"
```

{: .note }
> CloudHSM metric names vary by HSM type and SDK version. Enumerate what your
> cluster actually publishes before writing alarms against it:
>
> ```bash
> aws cloudwatch list-metrics --namespace AWS/CloudHSM \
>   --dimensions "Name=ClusterId,Value=${CLUSTER_ID}" \
>   --query 'Metrics[].MetricName' --output text | tr '\t' '\n' | sort -u
> ```

## Metric filters for log-derived alarms

Some conditions only exist in the log text, not as a metric.

```bash
# KMSInvalidStateException in application logs = a key is disabled or deleted
aws logs put-metric-filter \
  --log-group-name /aws/lambda/payment-processor \
  --filter-name kms-invalid-state \
  --filter-pattern '"KMSInvalidStateException"' \
  --metric-transformations \
    metricName=KMSInvalidState,metricNamespace=KeyMgmt,metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "kms-invalid-state-in-application" \
  --alarm-description "Application hit a disabled or deleted KMS key" \
  --namespace KeyMgmt --metric-name KMSInvalidState \
  --statistic Sum --period 60 --evaluation-periods 1 \
  --threshold 0 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$CRITICAL"

# HSM user management, from the CloudHSM audit log
aws logs put-metric-filter \
  --log-group-name "/aws/cloudhsm/${CLUSTER_ID}" \
  --filter-name hsm-user-management \
  --filter-pattern '?CN_CREATE_USER ?CN_DELETE_USER ?CN_SET_M_VALUE' \
  --metric-transformations \
    metricName=HsmUserManagement,metricNamespace=KeyMgmt,metricValue=1,defaultValue=0

aws cloudwatch put-metric-alarm \
  --alarm-name "cloudhsm-user-management-activity" \
  --namespace KeyMgmt --metric-name HsmUserManagement \
  --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 0 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$CRITICAL"
```

## Synthetic canaries — the only test that proves it works

Alarms tell you when a metric moved. A canary tells you whether encryption
actually works right now.

```python
# lambda/kms_canary.py — run every 5 minutes from EventBridge Scheduler
import base64
import json
import os
import time

import boto3

kms = boto3.client("kms")
cw = boto3.client("cloudwatch")
sns = boto3.client("sns")

KEYS = json.loads(os.environ["CANARY_KEYS"])       # {"alias": "region"}
TOPIC = os.environ["CRITICAL_TOPIC_ARN"]
CONTEXT = {"purpose": "canary"}


def check(alias: str, region: str) -> tuple[bool, float, str]:
    client = boto3.client("kms", region_name=region)
    start = time.perf_counter()
    try:
        blob = client.encrypt(
            KeyId=alias, Plaintext=b"canary", EncryptionContext=CONTEXT
        )["CiphertextBlob"]
        out = client.decrypt(
            CiphertextBlob=blob, EncryptionContext=CONTEXT
        )["Plaintext"]
        elapsed = (time.perf_counter() - start) * 1000
        if out != b"canary":
            return False, elapsed, "round trip returned wrong plaintext"
        return True, elapsed, ""
    except Exception as exc:                        # noqa: BLE001
        return False, (time.perf_counter() - start) * 1000, f"{type(exc).__name__}: {exc}"


def handler(event, context):
    failures = []
    for alias, region in KEYS.items():
        ok, ms, err = check(alias, region)
        cw.put_metric_data(
            Namespace="KeyMgmt/Canary",
            MetricData=[
                {"MetricName": "Success", "Value": 1 if ok else 0,
                 "Unit": "Count",
                 "Dimensions": [{"Name": "Alias", "Value": alias},
                                {"Name": "Region", "Value": region}]},
                {"MetricName": "RoundTripLatency", "Value": ms,
                 "Unit": "Milliseconds",
                 "Dimensions": [{"Name": "Alias", "Value": alias},
                                {"Name": "Region", "Value": region}]},
            ],
        )
        if not ok:
            failures.append(f"{alias} ({region}): {err}")

    if failures:
        sns.publish(
            TopicArn=TOPIC,
            Subject="CRITICAL: KMS canary failure",
            Message="Encrypt/decrypt round trip failed:\n\n" + "\n".join(failures),
        )
    return {"checked": len(KEYS), "failed": len(failures)}
```

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "kms-canary-failure" \
  --alarm-description "A KMS encrypt/decrypt round trip is failing" \
  --namespace KeyMgmt/Canary --metric-name Success \
  --statistic Minimum --period 300 --evaluation-periods 2 \
  --threshold 1 --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --alarm-actions "$CRITICAL"
```

{: .important }
> **`--treat-missing-data breaching` is deliberate here.** If the canary stops
> reporting, that is itself a failure — the Lambda died, the schedule broke, or
> the account is unreachable. A canary that fails silently is worse than no
> canary, because it produces false confidence.

Extend the canary to cover cross-Region multi-Region keys, which is the only real
test of your DR posture:

```python
def check_cross_region(alias: str, src: str, dst: str) -> tuple[bool, str]:
    """Encrypt in one Region, decrypt in another. Proves MRK replication works."""
    blob = boto3.client("kms", region_name=src).encrypt(
        KeyId=alias, Plaintext=b"mrk-canary", EncryptionContext=CONTEXT
    )["CiphertextBlob"]
    try:
        out = boto3.client("kms", region_name=dst).decrypt(
            CiphertextBlob=blob, EncryptionContext=CONTEXT
        )["Plaintext"]
        return out == b"mrk-canary", ""
    except Exception as exc:                        # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
```

## The dashboard

```bash
aws cloudwatch put-dashboard --dashboard-name key-management --dashboard-body '{
  "widgets": [
    {"type":"metric","x":0,"y":0,"width":12,"height":6,
     "properties":{"title":"Canary success by key",
       "metrics":[["KeyMgmt/Canary","Success","Alias","alias/prod/platform/s3-general","Region","us-east-1"],
                  ["...","alias/prod/data/rds-primary","Region","us-east-1"],
                  ["...","alias/prod/payments/pci-chd","Region","us-east-1"]],
       "stat":"Minimum","period":300,"region":"us-east-1","yAxis":{"left":{"min":0,"max":1}}}},
    {"type":"metric","x":12,"y":0,"width":12,"height":6,
     "properties":{"title":"Round-trip latency (p99)",
       "metrics":[["KeyMgmt/Canary","RoundTripLatency","Alias","alias/prod/platform/s3-general","Region","us-east-1"],
                  ["...","alias/prod/payments/pci-chd","Region","us-east-1"]],
       "stat":"p99","period":300,"region":"us-east-1"}},
    {"type":"metric","x":0,"y":6,"width":12,"height":6,
     "properties":{"title":"CloudHSM health",
       "metrics":[["AWS/CloudHSM","HsmUnhealthy","ClusterId","cluster-abcdefghijk"]],
       "stat":"Maximum","period":300,"region":"us-east-1"}},
    {"type":"log","x":12,"y":6,"width":12,"height":6,
     "properties":{"title":"Recent key administrative events",
       "query":"SOURCE \"/aws/cloudtrail/org\" | fields @timestamp, eventName, userIdentity.arn | filter eventSource = \"kms.amazonaws.com\" and eventName in [\"PutKeyPolicy\",\"ScheduleKeyDeletion\",\"DisableKey\",\"CreateGrant\"] | sort @timestamp desc | limit 25",
       "region":"us-east-1","view":"table"}}
  ]
}'
```

## The on-call runbook

| Alarm | First action | Then |
|:--|:--|:--|
| `kms-canary-failure` | `aws kms describe-key --key-id <alias>` — check `KeyState` | If `Disabled`, find the `DisableKey` event and its caller; `enable-key` if unauthorized |
| Custom key store disconnected | `describe-custom-key-stores` — read `ConnectionErrorCode` | Match the code to the table in [8.5]({% link docs/custom-key-store.md %}); most are `INVALID_CREDENTIALS` or `INSUFFICIENT_CLOUDHSM_HSMS` |
| `cloudhsm-unhealthy-hsm` | `describe-clusters` — which HSM, which AZ | `delete-hsm` the bad one, `create-hsm` a replacement; keys sync automatically |
| `kms-destructive-operations` | Read the CloudTrail event: who, when, from where | If unauthorized: `cancel-key-deletion` immediately, then `enable-key`, then revoke the principal |
| Decrypt volume anomaly | Identify the principal and the encryption contexts | Correlate with deploys and batch schedules; if unexplained, treat as an incident and consider `disable-key` |
| Throttling elevated | Check which operation and which principal | Enable data key caching; request a quota increase |
| Imported material expiring | Confirm you still hold the original material | Schedule the re-import ceremony now, not at day 6 |

---

[Next: 12. CI/CD Automation]({% link docs/cicd.md %}){: .btn .btn-primary }
