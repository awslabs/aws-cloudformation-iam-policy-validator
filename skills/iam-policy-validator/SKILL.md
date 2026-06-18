---
name: iam-policy-validator
description: Validate the IAM policies in a CloudFormation template against AWS IAM Access Analyzer before deploying, using the cfn-policy-validator CLI. Use when reviewing or gating a CloudFormation (or CDK-synthesized) template that defines IAM identity or resource policies, when asked to check a template for policy errors, public access, privilege escalation, or whether a change grants access beyond an approved baseline.
license: MIT-0
metadata:
  author: awslabs/aws-cloudformation-iam-policy-validator
  version: 1.0.0
---

# IAM policy validator for AWS CloudFormation

Validate the IAM policies embedded in a CloudFormation template against AWS IAM
Access Analyzer with the `cfn-policy-validator` CLI. The tool parses identity-
and resource-based policies from the template, resolves CloudFormation intrinsic
functions and pseudo parameters, and sends the resolved policies to Access
Analyzer. It does not reimplement policy analysis.

Install: `pip install cfn-policy-validator` (Python 3.9+).

## When to use which command

| Command | Answers | Backing API |
|---|---|---|
| `validate` | Is the policy correct and free of risky patterns? Returns `ERROR`, `SECURITY_WARNING`, `WARNING`, `SUGGESTION`. | `ValidatePolicy` + access previews |
| `check-no-new-access` | Does the policy grant anything beyond an approved reference policy? | `CheckNoNewAccess` |
| `check-access-not-granted` | Are these specific actions and/or resources NOT granted? | `CheckAccessNotGranted` |
| `check-no-public-access` | Can a resource policy grant public access? | `CheckNoPublicAccess` |
| `parse` | What policies does the template actually resolve to? (no Access Analyzer call) | none |

`validate` is the default for a general "review these policies" request. Reach
for `parse` when troubleshooting — it prints the resolved policies without any
AWS call, which is the fastest way to see what the tool extracted and how
intrinsics were evaluated.

## Workflow

1. **Get a template.** For raw CloudFormation, pass the `.json`/`.yaml`/`.yml`
   file directly — no pre-processing. For CDK, run `cdk synth` first and pass a
   `cdk.out/*.template.json` (it is CloudFormation). Do not synthesize
   implicitly; the synth is the user's step.
2. **Supply parameters if a policy depends on them.** Use `--parameters
   Key=Value [Key=Value ...]` or `--template-configuration-file file.json`. Only
   parameters referenced by IAM policies are required.
3. **Pick the command** and run it against a target that contains only policies
   the command can evaluate (see Scoping).
4. **Read the output.** It is JSON with `BlockingFindings` and
   `NonBlockingFindings`; the process exits `2` when any blocking finding is
   present and `0` otherwise. Report blocking findings first.

## Commands

```bash
# validate: correctness + best-practice + external-access findings
cfn-policy-validator validate --template-path ./template.yaml

# check-no-new-access: nothing beyond the reference policy
cfn-policy-validator check-no-new-access --template-path ./template.yaml \
  --reference-policy ./reference-policy.json --reference-policy-type identity

# check-access-not-granted: these actions/resources are not granted
cfn-policy-validator check-access-not-granted --template-path ./template.yaml \
  --actions "iam:CreateUser,iam:PutUserPolicy"

# check-no-public-access: resource policies cannot grant public access
cfn-policy-validator check-no-public-access --template-path ./template.yaml

# parse: print resolved policies, no Access Analyzer call (troubleshooting)
cfn-policy-validator parse --template-path ./template.yaml
```

`--region` is optional: it falls back to `AWS_REGION` / `AWS_DEFAULT_REGION`. Add
`--region <region>` only when neither is set in the environment — do not guess a
region when the environment already targets one, or the policies are validated
against the wrong region.

`--reference-policy-type` takes `identity` or `resource`. For
`check-access-not-granted`, at least one of `--actions` / `--resources` is
required (resources max 100 ARNs).

Full per-command flag reference: [references/cli.md](references/cli.md).

## Scoping each check to its own target

Run each check only over policies it can evaluate. Mixing identity and resource
policies in one template makes Access Analyzer reject the inapplicable ones and
produces misleading output.

- `check-no-public-access` evaluates **resource** policies only — not identity
  policies. The supported resource types are: `AWS::KMS::Key`,
  `AWS::Lambda::Permission`, `AWS::Lambda::LayerVersionPermission`,
  `AWS::S3::BucketPolicy`, `AWS::S3::AccessPoint`,
  `AWS::S3::MultiRegionAccessPoint`, `AWS::SQS::QueuePolicy`,
  `AWS::SNS::TopicPolicy`, `AWS::SecretsManager::ResourcePolicy`,
  `AWS::IAM::Role` (trust policy), `AWS::S3Tables::TableBucket`,
  `AWS::ApiGateway::RestApi`, `AWS::CodeArtifact::Domain`,
  `AWS::Backup::BackupVault`, `AWS::CloudTrail::Dashboard`,
  `AWS::CloudTrail::EventDataStore`, and `AWS::S3Express::AccessPoint`. A
  template with none of these has nothing for this check to evaluate.
- `check-no-new-access` and `check-access-not-granted` are typically run over
  **identity** policies (role inline/managed policies).
- `validate` accepts both.

When gating a whole stack, prefer one target per check over one mixed template.

## Interpreting findings

- Each finding has `findingType`, `code`, `message`, `resourceName`,
  `policyName`, and `details`. By default `ERROR` and `SECURITY_WARNING` are
  blocking; `WARNING` and `SUGGESTION` are not. A failing custom check
  (`check-no-new-access`, `check-access-not-granted`, `check-no-public-access`)
  is surfaced as a blocking `SECURITY_WARNING`.
- Change which types block with `--treat-finding-type-as-blocking` (e.g. pass
  `NONE` to make everything non-blocking). Suppress a known finding with
  `--ignore-finding` by code, resource name, or `RESOURCE.CODE`.
- The exit code is the machine signal: `0` = no blocking findings, `2` = at
  least one. In CI, gate the job on the exit code.

## Credentials and required access

The checks call Access Analyzer and run access previews, so they need AWS
credentials. They resolve through the standard boto3 chain (`--profile`,
`AWS_PROFILE`, `~/.aws`, or environment variables); region resolves from
`--region` or `AWS_REGION` / `AWS_DEFAULT_REGION`. The principal needs:
`access-analyzer:ValidatePolicy`, `access-analyzer:CheckNoNewAccess`,
`access-analyzer:CheckAccessNotGranted`, `access-analyzer:CheckNoPublicAccess`,
`access-analyzer:CreateAccessPreview`, `access-analyzer:GetAccessPreview`,
`access-analyzer:ListAccessPreviewFindings`, `access-analyzer:ListAnalyzers`,
`access-analyzer:CreateAnalyzer` (only if the account has no analyzer yet),
`iam:GetPolicy`, `iam:GetPolicyVersion`, `s3:ListAllMyBuckets`,
`cloudformation:ListExports`, and `ssm:GetParameter`. Creating an analyzer also
needs `iam:CreateServiceLinkedRole` scoped to `access-analyzer.amazonaws.com`. A
`PermissionError` / `AccessDenied` from a check usually means one of these is
missing. `parse` makes no AWS call but still constructs a client, so a resolvable
region/profile is expected.
