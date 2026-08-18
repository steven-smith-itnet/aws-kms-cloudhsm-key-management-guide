---
title: 8.3 Users & Keys
parent: 8. CloudHSM & HSM-Backed Tiers
nav_order: 3
---

# Activation, Users, and Key Generation
{: .no_toc }

Inside the HSM there is a second, completely separate identity system. IAM does
not reach here — these are HSM users with HSM passwords and HSM roles.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Two authorization worlds

```text
   AWS IAM world                        HSM world
   ─────────────                        ─────────
   Who may create/delete an HSM?        Who may create a key?
   Who may see cluster metadata?        Who may use a key to sign?
   Who may take a backup?               Who may add another HSM user?

   Controlled by: IAM policies,         Controlled by: HSM user accounts,
   SCPs, key policies                   roles, passwords, quorum

   Logged to: CloudTrail                Logged to: HSM audit log
                                        (streamed to CloudWatch Logs)
```

{: .important }
> **An IAM administrator with `cloudhsm:*` cannot read your keys.** They can
> delete the cluster — which destroys the keys — but they cannot use them. That
> separation is the core of the CloudHSM value proposition, and it is also why
> losing HSM credentials is unrecoverable: there is no IAM path to override them.

## HSM roles

| Role | CLI value | Can do | Cannot do |
|:--|:--|:--|:--|
| **Precrypto Officer (PRECO)** | — | Only exists before activation; becomes the admin CO | Anything else |
| **Crypto Officer (CO / admin)** | `admin` | Create/delete users, change passwords, manage quorum, zeroize | **Use keys for crypto operations** |
| **Crypto User (CU)** | `crypto-user` | Generate, use, wrap, delete keys they own; share keys | Manage users |
| **Appliance User (AU)** | — | Cloning and synchronization; used internally by AWS | Anything you configure |

{: .warning }
> **The CO cannot use keys, and the CU cannot manage users.** This separation is
> enforced in hardware and cannot be bypassed. It is exactly the separation of
> duties auditors ask for — and it means you need at least two credentials, held
> by different people, to run the cluster.

## Step 1 — Install CloudHSM CLI (Client SDK 5)

On the client instance from [8.1]({% link docs/cloudhsm-provision.md %}):

```bash
# Amazon Linux 2023 / RHEL 9
sudo dnf install -y https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.x86_64.rpm

# Ubuntu 22.04
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Jammy/cloudhsm-cli_latest_u22.04_amd64.deb
sudo apt-get install -y ./cloudhsm-cli_latest_u22.04_amd64.deb

/opt/cloudhsm/bin/cloudhsm-cli --version
```

{: .note }
> Package URLs and OS support change between SDK releases. Check the
> [CloudHSM Client SDK download page](https://docs.aws.amazon.com/cloudhsm/latest/userguide/install-and-configure-client-5.html)
> for the current artifact for your distribution. Client SDK 5 is the supported
> line; SDK 3 (`cloudhsm_mgmt_util`, `key_mgmt_util`) is legacy.

## Step 2 — Configure the client

The client needs the HSM's IP address and your trust anchor certificate.

```bash
# Fetch the trust anchor you published during the ceremony
sudo aws s3 cp \
  "s3://keymgmt-artifacts-111122223333/cloudhsm/${CLUSTER_ID}/customerCA.crt" \
  /opt/cloudhsm/etc/customerCA.crt

sudo chmod 644 /opt/cloudhsm/etc/customerCA.crt

# Point the CLI at any one HSM — it discovers the rest of the cluster
HSM_IP=$(aws cloudhsmv2 describe-clusters --filters clusterIds="$CLUSTER_ID" \
  --query 'Clusters[0].Hsms[0].EniIp' --output text)

sudo /opt/cloudhsm/bin/configure-cli -a "$HSM_IP"

# Verify connectivity and that the cluster certificate chains to YOUR CA
/opt/cloudhsm/bin/cloudhsm-cli cluster identify
```

```text
{
  "error_code": 0,
  "data": {
    "hsms": [
      { "hostname": "10.20.10.15", "state": "connected", "state_message": "" },
      { "hostname": "10.20.11.22", "state": "connected", "state_message": "" }
    ]
  }
}
```

{: .warning }
> If `cluster identify` reports a TLS or certificate error, **stop**. It means
> the HSM's certificate does not chain to the `customerCA.crt` you installed —
> either you copied the wrong trust anchor, or something is wrong. This check is
> the entire point of the initialization ceremony; do not work around it with a
> flag.

## Step 3 — Activate the cluster

Activation converts the PRECO into the admin Crypto Officer and sets its
password. Until this happens, the cluster is `INITIALIZED` but unusable.

{: .account }
> **Ceremony step.** Two custodians. The admin password should be generated
> randomly, split between custodians (or stored in a break-glass vault with dual
> control), and never typed into a shared terminal that logs to a retained
> scrollback.

```bash
/opt/cloudhsm/bin/cloudhsm-cli interactive
```

```text
aws-cloudhsm > cluster activate
Enter password:              # new admin (CO) password, 8-32 chars
Confirm password:
{
  "error_code": 0,
  "data": "Cluster activation successful"
}
```

```bash
# Cluster state should now be ACTIVE
aws cloudhsmv2 describe-clusters --filters clusterIds="$CLUSTER_ID" \
  --query 'Clusters[0].State' --output text
```

```text
ACTIVE
```

## Step 4 — Create users

```bash
export CLOUDHSM_ROLE=admin
export CLOUDHSM_PIN="admin:<the-admin-password>"

/opt/cloudhsm/bin/cloudhsm-cli interactive
```

```text
aws-cloudhsm > login --username admin --role admin
Enter password:
{ "error_code": 0, "data": { "username": "admin", "role": "admin" } }

# --- A second Crypto Officer, so one lost password is not fatal --------------
aws-cloudhsm > user create --username co-backup --role admin
Enter password:
Confirm password:
{ "error_code": 0, "data": { "user": { "username": "co-backup", "role": "admin" } } }

# --- The crypto user your applications authenticate as ----------------------
aws-cloudhsm > user create --username app-payments --role crypto-user
Enter password:
Confirm password:

# --- The crypto user KMS uses for a custom key store ------------------------
#     The name MUST be exactly "kmsuser" — KMS looks for it by name.
aws-cloudhsm > user create --username kmsuser --role crypto-user
Enter password:
Confirm password:

aws-cloudhsm > user list
{
  "error_code": 0,
  "data": {
    "users": [
      { "username": "admin",        "role": "admin",        "locked": "false", "mfa": [], "cluster-coverage": "full" },
      { "username": "co-backup",    "role": "admin",        "locked": "false", "mfa": [], "cluster-coverage": "full" },
      { "username": "app-payments", "role": "crypto-user",  "locked": "false", "mfa": [], "cluster-coverage": "full" },
      { "username": "kmsuser",      "role": "crypto-user",  "locked": "false", "mfa": [], "cluster-coverage": "full" },
      { "username": "app",          "role": "internal(AU)", "locked": "false", "mfa": [], "cluster-coverage": "full" }
    ]
  }
}
```

{: .important }
> **`cluster-coverage: full` matters.** It means the user exists on every HSM in
> the cluster. If it reads anything else, one HSM missed the update and
> authentication will fail intermittently depending on which HSM the client
> connects to — a genuinely miserable bug to diagnose. Re-run the user creation,
> or check for a `DEGRADED` HSM.

### Password management

```text
# Change your own password
aws-cloudhsm > user change-password --username app-payments --role crypto-user

# A CO can reset another user's password
aws-cloudhsm > login --username admin --role admin
aws-cloudhsm > user change-password --username app-payments --role crypto-user

# Delete a decommissioned user (this does NOT delete keys they own — see below)
aws-cloudhsm > user delete --username app-legacy --role crypto-user
```

{: .warning }
> **Deleting a crypto user can orphan their keys.** Keys in CloudHSM have an
> owner. If you delete the owning CU without first transferring or sharing the
> keys, they may become unusable. Before removing a CU, run `key list` as that
> user, and either share the keys to the successor user or export/re-create them.

## Step 5 — Quorum authentication (MofN)

For high-value clusters, require *M of N* Crypto Officers to approve
user-management operations. This is the control that prevents a single
compromised admin credential from adding a new crypto user.

```text
# Each CO registers a quorum token-signing key pair
aws-cloudhsm > quorum token-sign register --public-key /home/ec2-user/co1-public.pem

# Set the quorum requirement: 2 of the registered COs
aws-cloudhsm > quorum token-sign set-quorum-value --service user --value 2

aws-cloudhsm > quorum token-sign list-quorum-values
{
  "error_code": 0,
  "data": { "user": 2, "quorum": 2 }
}
```

Once set, a `user create` produces a token that must be signed by two COs before
it takes effect:

```text
aws-cloudhsm > quorum token-sign generate --service user --approval-file /tmp/req.json
# CO #1 signs
aws-cloudhsm > quorum token-sign sign --approval-file /tmp/req.json --key-file co1.key
# CO #2 signs
aws-cloudhsm > quorum token-sign sign --approval-file /tmp/req.json --key-file co2.key
aws-cloudhsm > quorum token-sign submit --signed-token-file /tmp/req.json.signed
```

{: .note }
> Exact quorum subcommands vary between Client SDK 5 minor versions. Verify
> against `cloudhsm-cli quorum token-sign --help` on the version you installed,
> and rehearse the whole flow in a dev cluster before enabling quorum in
> production — a misconfigured quorum can lock you out of user management
> entirely.

## Step 6 — Generate keys

```bash
export CLOUDHSM_ROLE=crypto-user
export CLOUDHSM_PIN="app-payments:<password>"
/opt/cloudhsm/bin/cloudhsm-cli interactive
```

```text
aws-cloudhsm > login --username app-payments --role crypto-user

# --- AES-256 symmetric key, non-extractable ---------------------------------
aws-cloudhsm > key generate-symmetric aes \
    --label payments-dek-2026 \
    --key-length-bytes 32 \
    --attributes extractable=false sign=false verify=false \
                 encrypt=true decrypt=true token=true

{
  "error_code": 0,
  "data": {
    "key": {
      "key-reference": "0x00000000005c0334",
      "key-info": { "key-owners": [{ "username": "app-payments", "key-coverage": "full" }] },
      "attributes": {
        "key-type": "aes", "label": "payments-dek-2026", "id": "",
        "check-value": "0x8e5f2a", "class": "secret-key",
        "encrypt": true, "decrypt": true, "token": true,
        "extractable": false, "never-extractable": true, "sensitive": true
      }
    }
  }
}

# --- RSA-4096 signing key pair ----------------------------------------------
aws-cloudhsm > key generate-asymmetric-pair rsa \
    --public-label code-signing-2026-pub \
    --private-label code-signing-2026-priv \
    --modulus-size-bits 4096 \
    --public-exponent 65537 \
    --attributes sign=true verify=true extractable=false token=true

# --- EC P-384 key pair ------------------------------------------------------
aws-cloudhsm > key generate-asymmetric-pair ec \
    --public-label tls-ec-pub \
    --private-label tls-ec-priv \
    --curve secp384r1 \
    --attributes sign=true verify=true extractable=false token=true

aws-cloudhsm > key list --verbose
```

### Attributes that matter

| Attribute | Set it to | Why |
|:--|:--|:--|
| `extractable` | `false` | The key can never leave the HSM, even wrapped. This is the whole reason you bought an HSM |
| `never-extractable` | (derived) | Reports `true` if the key has *always* been non-extractable — the stronger assurance |
| `sensitive` | `true` | The value cannot be read even by the owner |
| `token` | `true` | Persistent. `false` means a session key that vanishes on logout |
| `encrypt` / `decrypt` / `sign` / `verify` / `wrap` / `unwrap` | Only what is needed | Narrow the key's permitted mechanisms |

{: .important }
> **Set `extractable=false` unless you have a specific, written reason not to.**
> An extractable key can be wrapped out of the HSM under another key, which
> means a compromised crypto user can exfiltrate it. The moment you allow
> extraction, you have a software key that happens to be stored in an HSM — and
> most of your FIPS 140-3 Level 3 claim evaporates.

### Key sharing between users

```text
# Let a second CU use a key without owning it
aws-cloudhsm > key share --filter attr.label=payments-dek-2026 \
                         --username app-reporting --role crypto-user

aws-cloudhsm > key list --filter attr.label=payments-dek-2026 --verbose
# -> shared-users now includes app-reporting

aws-cloudhsm > key unshare --filter attr.label=payments-dek-2026 \
                           --username app-reporting --role crypto-user
```

## Step 7 — Stream the HSM audit log to CloudWatch

The HSM keeps its own audit log, entirely separate from CloudTrail. It records
logins, key operations, and user management inside the HSM boundary.

```bash
# Enable audit log delivery (per-cluster)
aws cloudhsmv2 modify-cluster \
  --cluster-id "$CLUSTER_ID" \
  --hsm-type hsm2m.medium

# Audit logs land in CloudWatch Logs under this group
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/cloudhsm/${CLUSTER_ID}" \
  --query 'logGroups[].{Name:logGroupName,Retention:retentionInDays}'

# Set retention and encrypt the log group with a CMK
aws logs put-retention-policy \
  --log-group-name "/aws/cloudhsm/${CLUSTER_ID}" \
  --retention-in-days 2557

aws logs associate-kms-key \
  --log-group-name "/aws/cloudhsm/${CLUSTER_ID}" \
  --kms-key-id alias/prod/platform/s3-general
```

```bash
# Query for user-management events — the ones that should be rare and reviewed
aws logs start-query \
  --log-group-name "/aws/cloudhsm/${CLUSTER_ID}" \
  --start-time "$(date -u -d '7 days ago' +%s)" \
  --end-time "$(date -u +%s)" \
  --query-string 'fields @timestamp, @message
    | filter @message like /CN_CREATE_USER|CN_DELETE_USER|CN_CHANGE_PSWD|CN_SET_M_VALUE/
    | sort @timestamp desc
    | limit 100'
```

{: .tip }
> **The HSM audit log is the evidence CloudTrail cannot give you.** CloudTrail
> shows that someone called `cloudhsmv2:DescribeClusters`; the HSM audit log
> shows that `app-payments` logged in and performed 14,000 sign operations. For
> PCI DSS and FIPS-relevant audits, this is the log they actually want. Ship it
> to your SIEM alongside CloudTrail — see
> [Logging &amp; SIEM]({% link docs/logging-siem.md %}).

## Credential handling for applications

Applications authenticate to the HSM with a username and password. Store them in
Secrets Manager, encrypted with a CMK, and never in an environment file baked
into an AMI or image layer.

```bash
aws secretsmanager create-secret \
  --name prod/cloudhsm/app-payments \
  --description "CloudHSM crypto-user credentials for the payments service" \
  --kms-key-id alias/prod/secrets/app-secrets \
  --secret-string '{"username":"app-payments","password":"REPLACE_ME","role":"crypto-user"}'
```

```python
import json, os, boto3

sm = boto3.client("secretsmanager")
creds = json.loads(
    sm.get_secret_value(SecretId="prod/cloudhsm/app-payments")["SecretString"]
)

# Client SDK 5 reads these two environment variables
os.environ["CLOUDHSM_ROLE"] = creds["role"]
os.environ["CLOUDHSM_PIN"] = f"{creds['username']}:{creds['password']}"
```

{: .warning }
> **`CLOUDHSM_PIN` in an environment variable is visible in `/proc/<pid>/environ`
> and in most container introspection.** It is a pragmatic default, not a strong
> control. For higher-assurance deployments, use the SDK's credential file with
> restrictive permissions, or fetch the secret and pass it via the SDK's
> programmatic login rather than the process environment.

## Users &amp; keys checklist

| # | Check | Command |
|:--|:--|:--|
| 1 | Cluster state is `ACTIVE` | `aws cloudhsmv2 describe-clusters` |
| 2 | At least two CO accounts exist | `user list` |
| 3 | `kmsuser` CU exists (if using a custom key store) | `user list` |
| 4 | All users report `cluster-coverage: full` | `user list` |
| 5 | Quorum configured for user management | `quorum token-sign list-quorum-values` |
| 6 | Keys are `extractable: false` / `never-extractable: true` | `key list --verbose` |
| 7 | Credentials stored in Secrets Manager, not on disk | `aws secretsmanager list-secrets` |
| 8 | HSM audit log flowing to CloudWatch with retention set | `aws logs describe-log-groups` |
| 9 | Admin password escrowed under dual control | Ceremony record |

---

[Next: 8.4 Application Integration]({% link docs/cloudhsm-apps.md %}){: .btn .btn-primary }
