---
name: iam-policy-validator
description: Validate the IAM policies in a CloudFormation template against AWS IAM Access Analyzer before deploying, using the cfn-policy-validator CLI. Use when reviewing or gating a CloudFormation (or CDK-synthesized) template that defines IAM identity or resource policies, when asked to check a template for policy errors, public access, privilege escalation, or whether a change grants access beyond an approved baseline.
license: MIT-0
metadata:
  author: awslabs/aws-cloudformation-iam-policy-validator
  version: 1.0.0
---

# IAM policy validator for AWS CloudFormation

Use the `cfn-policy-validator` CLI to validate the IAM policies in a
CloudFormation template against AWS IAM Access Analyzer before deploying. The
tool extracts identity- and resource-based policies from the template, resolves
intrinsic functions and pseudo parameters, and runs them through Access
Analyzer. Install with `pip install cfn-policy-validator`.

Discover the exact commands and flags by running `cfn-policy-validator --help`
and `cfn-policy-validator <command> --help`.

## When to use which command

- `validate` — general "review these policies": correctness and best-practice
  findings. The default for an open-ended review request.
- `check-no-new-access` — confirm a policy grants nothing beyond an approved
  reference policy.
- `check-access-not-granted` — confirm specific actions or resources are not
  granted.
- `check-no-public-access` — confirm a resource policy cannot grant public
  access. Applies to resource policies only; a template with none has nothing
  for it to evaluate.
- `parse` — print the resolved policies without calling Access Analyzer. Use to
  troubleshoot what the tool extracted and how intrinsics were evaluated.

## Preparing input

- Raw CloudFormation: pass the template directly; the tool resolves
  `!Ref`/`!Sub`/`!GetAtt` itself.
- CDK: run `cdk synth` first and pass a `cdk.out/*.template.json`. Do not
  synthesize implicitly; that is the user's step.
- When a policy depends on template parameters, supply them (`--parameters` or a
  template-configuration file) so the policy resolves.

## Reading the result

Each check returns JSON with `BlockingFindings` and `NonBlockingFindings` and
exits `2` when any blocking finding is present, `0` otherwise. Report blocking
findings first. In CI, gate on the exit code.

## Example

Reviewing a template before deploy:

```
cfn-policy-validator validate --template-path ./template.yaml
```

A problem policy produces a `BlockingFindings` entry and exit code `2`:

```json
{
  "BlockingFindings": [
    {"findingType": "ERROR", "code": "INVALID_ACTION", "resourceName": "MyRole"}
  ],
  "NonBlockingFindings": []
}
```

A clean template returns empty findings and exit code `0`.

## Credentials

The checks call Access Analyzer (including access previews), so they need AWS
credentials and a region (`--region`, else `AWS_REGION` / `AWS_DEFAULT_REGION`).
An `AccessDenied` error names the missing Access Analyzer or IAM permission —
grant it and retry. The full required policy is in the project README:
https://github.com/awslabs/aws-cloudformation-iam-policy-validator#iam-policy-required-to-run-the-iam-policy-validator-for-aws-cloudformation
