---
title: 5.4 CloudFormation
parent: 5. Creating Keys
nav_order: 4
---

# Creating a CMK with CloudFormation
{: .no_toc }

The AWS-native IaC path. Choose it when your organization mandates
CloudFormation, when you need StackSets for multi-account rollout, or when keys
are provisioned through Service Catalog.
{: .fs-5 .fw-300 }

## On this page
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## When CloudFormation beats Terraform here

| Situation | Why CloudFormation |
|:--|:--|
| Rolling one key design across 50 accounts | **StackSets** with service-managed permissions deploy into every account in an OU automatically, including new accounts |
| Self-service key requests | **Service Catalog** products wrap a template with constrained parameters |
| No state file to manage | State lives in the CloudFormation service, not an S3 bucket you must secure |
| Existing AWS-native CI/CD | CodePipeline + CloudFormation change sets |

| Situation | Why Terraform instead |
|:--|:--|
| Complex conditional policy composition | `aws_iam_policy_document` is far more expressive than `Fn::If` chains |
| Multi-cloud estate | One tool, one language |
| CloudHSM cluster provisioning | See the note below |

{: .warning }
> **CloudFormation has no native CloudHSM v2 resource type.** There is no
> `AWS::CloudHSMV2::Cluster`. Provisioning a cluster from CloudFormation requires
> a custom resource backed by a Lambda function that calls the `cloudhsmv2` API.
> For that reason this guide uses Terraform and the CLI for the CloudHSM work in
> [Section 8]({% link docs/cloudhsm.md %}). Verify against the current
> [CloudFormation resource reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html)
> before assuming this is still true.

## The template

`cloudformation/kms-key.yaml`

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  Customer managed KMS key with alias, rotation, and a least-privilege key
  policy separating administration from cryptographic use.

Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label: { default: "Key identity" }
        Parameters: [AliasSuffix, KeyDescription, KeySpec, KeyUsage]
      - Label: { default: "Lifecycle" }
        Parameters: [EnableRotation, RotationPeriodDays, DeletionWindowDays, MultiRegion]
      - Label: { default: "Access" }
        Parameters: [KeyAdministratorArn, WorkloadAccountId, ViaService]
      - Label: { default: "Tagging" }
        Parameters: [Environment, DataClass, Owner, CostCenter]

Parameters:
  AliasSuffix:
    Type: String
    Description: Alias without the 'alias/' prefix, e.g. prod/platform/s3-general
    AllowedPattern: "^(?!aws/)[a-zA-Z0-9:/_-]+$"
    ConstraintDescription: Must not begin with 'aws/' (reserved namespace).

  KeyDescription:
    Type: String
    MinLength: 8
    MaxLength: 8192

  KeySpec:
    Type: String
    Default: SYMMETRIC_DEFAULT
    AllowedValues:
      - SYMMETRIC_DEFAULT
      - RSA_2048
      - RSA_3072
      - RSA_4096
      - ECC_NIST_P256
      - ECC_NIST_P384
      - ECC_NIST_P521
      - ECC_SECG_P256K1
      - HMAC_256
      - HMAC_384
      - HMAC_512

  KeyUsage:
    Type: String
    Default: ENCRYPT_DECRYPT
    AllowedValues: [ENCRYPT_DECRYPT, SIGN_VERIFY, GENERATE_VERIFY_MAC]

  EnableRotation:
    Type: String
    Default: "true"
    AllowedValues: ["true", "false"]

  RotationPeriodDays:
    Type: Number
    Default: 365
    MinValue: 90
    MaxValue: 2560

  DeletionWindowDays:
    Type: Number
    Default: 30
    MinValue: 7
    MaxValue: 30

  MultiRegion:
    Type: String
    Default: "false"
    AllowedValues: ["true", "false"]
    Description: IMMUTABLE after creation. Changing this replaces the key.

  KeyAdministratorArn:
    Type: String
    Description: IAM role ARN permitted to administer (not use) the key.

  WorkloadAccountId:
    Type: String
    Default: ""
    AllowedPattern: "^([0-9]{12})?$"
    Description: Optional 12-digit account ID granted cryptographic use.

  ViaService:
    Type: String
    Default: ""
    Description: >-
      Optional kms:ViaService restriction, e.g. s3.us-east-1.amazonaws.com.
      Leave blank for unrestricted use by the granted principals.

  Environment:
    Type: String
    AllowedValues: [prod, stage, dev]
  DataClass:
    Type: String
    AllowedValues: [restricted, confidential, internal, public]
  Owner:
    Type: String
  CostCenter:
    Type: String

Conditions:
  IsSymmetric:      !Equals [!Ref KeySpec, SYMMETRIC_DEFAULT]
  RotationRequested: !Equals [!Ref EnableRotation, "true"]
  # Rotation is only valid on symmetric keys, regardless of what was asked for.
  DoRotation:       !And [!Condition IsSymmetric, !Condition RotationRequested]
  IsMultiRegion:    !Equals [!Ref MultiRegion, "true"]
  HasWorkloadAccount: !Not [!Equals [!Ref WorkloadAccountId, ""]]
  HasViaService:    !Not [!Equals [!Ref ViaService, ""]]

Resources:
  Key:
    Type: AWS::KMS::Key
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      Description: !Ref KeyDescription
      KeySpec: !Ref KeySpec
      KeyUsage: !Ref KeyUsage
      MultiRegion: !If [IsMultiRegion, true, false]
      EnableKeyRotation: !If [DoRotation, true, false]
      RotationPeriodInDays: !If [DoRotation, !Ref RotationPeriodDays, !Ref "AWS::NoValue"]
      PendingWindowInDays: !Ref DeletionWindowDays
      Enabled: true
      KeyPolicy:
        Version: "2012-10-17"
        Id: !Sub "key-policy-${AliasSuffix}"
        Statement:
          - Sid: EnableIAMUserPermissions
            Effect: Allow
            Principal:
              AWS: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"

          - Sid: AllowKeyAdministration
            Effect: Allow
            Principal:
              AWS: !Ref KeyAdministratorArn
            Action:
              - kms:Create*
              - kms:Describe*
              - kms:Enable*
              - kms:List*
              - kms:Put*
              - kms:Update*
              - kms:Revoke*
              - kms:Disable*
              - kms:Get*
              - kms:TagResource
              - kms:UntagResource
              - kms:ScheduleKeyDeletion
              - kms:CancelKeyDeletion
              - kms:ReplicateKey
              - kms:RotateKeyOnDemand
            Resource: "*"

          - !If
            - HasWorkloadAccount
            - Sid: AllowWorkloadAccountUse
              Effect: Allow
              Principal:
                AWS: !Sub "arn:${AWS::Partition}:iam::${WorkloadAccountId}:root"
              Action:
                - kms:Encrypt
                - kms:Decrypt
                - kms:ReEncrypt*
                - kms:GenerateDataKey*
                - kms:DescribeKey
              Resource: "*"
              Condition: !If
                - HasViaService
                - StringEquals:
                    kms:ViaService: !Ref ViaService
                    kms:CallerAccount: !Ref WorkloadAccountId
                - StringEquals:
                    kms:CallerAccount: !Ref WorkloadAccountId
            - !Ref "AWS::NoValue"

          - !If
            - HasWorkloadAccount
            - Sid: AllowGrantsForAWSResources
              Effect: Allow
              Principal:
                AWS: !Sub "arn:${AWS::Partition}:iam::${WorkloadAccountId}:root"
              Action:
                - kms:CreateGrant
                - kms:ListGrants
                - kms:RevokeGrant
              Resource: "*"
              Condition:
                Bool:
                  kms:GrantIsForAWSResource: "true"
            - !Ref "AWS::NoValue"

      Tags:
        - { Key: Environment, Value: !Ref Environment }
        - { Key: DataClass,   Value: !Ref DataClass }
        - { Key: Owner,       Value: !Ref Owner }
        - { Key: CostCenter,  Value: !Ref CostCenter }
        - { Key: Alias,       Value: !Ref AliasSuffix }
        - { Key: ManagedBy,   Value: cloudformation }

  Alias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub "alias/${AliasSuffix}"
      TargetKeyId: !Ref Key

  # Publish the ARN so workload stacks can import it without cross-stack refs
  KeyArnParameter:
    Type: AWS::SSM::Parameter
    Properties:
      Name: !Sub "/keymgmt/${Environment}/${AliasSuffix}/arn"
      Type: String
      Value: !GetAtt Key.Arn
      Description: !Sub "KMS key ARN for ${AliasSuffix}"

Outputs:
  KeyId:
    Description: KMS key ID
    Value: !Ref Key
    Export:
      Name: !Sub "${AWS::StackName}-KeyId"
  KeyArn:
    Description: KMS key ARN
    Value: !GetAtt Key.Arn
    Export:
      Name: !Sub "${AWS::StackName}-KeyArn"
  AliasName:
    Description: Alias name
    Value: !Ref Alias
    Export:
      Name: !Sub "${AWS::StackName}-AliasName"
```

{: .important }
> **`DeletionPolicy: Retain` and `UpdateReplacePolicy: Retain` are mandatory for
> key resources.** Without them, deleting the stack schedules the key for
> deletion, and any property change that requires replacement (`MultiRegion`,
> `KeySpec`, `KeyUsage`) silently destroys the original. `Retain` orphans the key
> from the stack instead — recoverable, unlike the alternative.

## Deploy

```bash
cat > cloudformation/kms-key-params-prod.json <<'PARAMS'
[
  { "ParameterKey": "AliasSuffix",         "ParameterValue": "prod/platform/s3-general" },
  { "ParameterKey": "KeyDescription",      "ParameterValue": "Prod platform key for general S3 object encryption" },
  { "ParameterKey": "KeySpec",             "ParameterValue": "SYMMETRIC_DEFAULT" },
  { "ParameterKey": "KeyUsage",            "ParameterValue": "ENCRYPT_DECRYPT" },
  { "ParameterKey": "EnableRotation",      "ParameterValue": "true" },
  { "ParameterKey": "RotationPeriodDays",  "ParameterValue": "365" },
  { "ParameterKey": "DeletionWindowDays",  "ParameterValue": "30" },
  { "ParameterKey": "MultiRegion",         "ParameterValue": "false" },
  { "ParameterKey": "KeyAdministratorArn", "ParameterValue": "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_KeyAdministrator_abc123" },
  { "ParameterKey": "WorkloadAccountId",   "ParameterValue": "444455556666" },
  { "ParameterKey": "ViaService",          "ParameterValue": "s3.us-east-1.amazonaws.com" },
  { "ParameterKey": "Environment",         "ParameterValue": "prod" },
  { "ParameterKey": "DataClass",           "ParameterValue": "confidential" },
  { "ParameterKey": "Owner",               "ParameterValue": "platform@yourcompany.com" },
  { "ParameterKey": "CostCenter",          "ParameterValue": "CC-4417" }
]
PARAMS

# 1. Lint before you deploy
aws cloudformation validate-template \
  --template-body file://cloudformation/kms-key.yaml

pip install cfn-lint && cfn-lint cloudformation/kms-key.yaml

# 2. Create a change set rather than deploying blind
aws cloudformation deploy \
  --stack-name kms-prod-platform-s3-general \
  --template-file cloudformation/kms-key.yaml \
  --parameter-overrides file://cloudformation/kms-key-params-prod.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-execute-changeset

# 3. Review, then execute the change set the previous command printed
aws cloudformation describe-change-set \
  --change-set-name arn:aws:cloudformation:us-east-1:111122223333:changeSet/awscli-cloudformation-package-deploy-1234567890 \
  --query 'Changes[].ResourceChange.{Action:Action,Type:ResourceType,Replacement:Replacement,Id:LogicalResourceId}' \
  --output table

aws cloudformation execute-change-set \
  --change-set-name arn:aws:cloudformation:us-east-1:111122223333:changeSet/awscli-cloudformation-package-deploy-1234567890
```

{: .warning }
> **Watch the `Replacement` column.** For a KMS key, `Replacement: True` means
> CloudFormation will create a new key and (absent `Retain`) delete the old one.
> Every object encrypted under the old key becomes undecryptable when it
> finishes. If you ever see `Replacement: True` on a `AWS::KMS::Key`, stop and
> work out which immutable property you changed.

Verify:

```bash
aws cloudformation describe-stacks \
  --stack-name kms-prod-platform-s3-general \
  --query 'Stacks[0].Outputs' --output table
```

## Multi-account rollout with StackSets

This is where CloudFormation earns its place: deploying the same key design into
every account in an OU, including accounts that do not exist yet.

```bash
# 1. Enable trusted access between Organizations and CloudFormation (once)
aws organizations enable-aws-service-access \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com

# 2. Create the stack set with service-managed permissions
aws cloudformation create-stack-set \
  --stack-set-name org-baseline-kms-keys \
  --template-body file://cloudformation/kms-key.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=true \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters file://cloudformation/kms-key-params-prod.json \
  --description "Baseline customer managed keys for every workload account"

# 3. Target the Workloads OU across two Regions
WORKLOADS_OU=$(aws organizations list-organizational-units-for-parent \
  --parent-id "$(aws organizations list-roots --query 'Roots[0].Id' --output text)" \
  --query "OrganizationalUnits[?Name=='Workloads'].Id" --output text)

aws cloudformation create-stack-instances \
  --stack-set-name org-baseline-kms-keys \
  --deployment-targets OrganizationalUnitIds="$WORKLOADS_OU" \
  --regions us-east-1 us-west-2 \
  --operation-preferences \
    FailureTolerancePercentage=0,MaxConcurrentPercentage=25,RegionConcurrencyType=PARALLEL

# 4. Watch it roll out
aws cloudformation list-stack-instances \
  --stack-set-name org-baseline-kms-keys \
  --query 'Summaries[].{Account:Account,Region:Region,Status:StackInstanceStatus.DetailedStatus}' \
  --output table
```

{: .tip }
> `RetainStacksOnAccountRemoval=true` means that if an account leaves the
> organization, its keys are **not** deleted with it. For key material this is
> almost always what you want — the data encrypted under those keys probably
> leaves with the account too.

## Drift detection

CloudFormation can tell you when someone edited a key policy in the Console
behind your back.

```bash
DRIFT_ID=$(aws cloudformation detect-stack-drift \
  --stack-name kms-prod-platform-s3-general \
  --query StackDriftDetectionId --output text)

# Poll until DETECTION_COMPLETE
aws cloudformation describe-stack-drift-detection-status \
  --stack-drift-detection-id "$DRIFT_ID"

aws cloudformation describe-stack-resource-drifts \
  --stack-name kms-prod-platform-s3-general \
  --stack-resource-drift-status-filters MODIFIED DELETED \
  --query 'StackResourceDrifts[].{Id:LogicalResourceId,Status:StackResourceDriftStatus,Diff:PropertyDifferences}'
```

Schedule this nightly — see [CI/CD Automation]({% link docs/cicd.md %}).

---

[Next: 5.5 Python SDK]({% link docs/kms-python.md %}){: .btn .btn-primary }
