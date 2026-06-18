# cfn-policy-validator CLI reference

Command: `cfn-policy-validator <subcommand> [flags]`. Subcommands: `validate`,
`check-no-new-access`, `check-access-not-granted`, `check-no-public-access`,
`parse`.

## Flags common to every subcommand

| Flag | Required | Value | Description |
|---|---|---|---|
| `--template-path` | Yes | FILE | Path to the CloudFormation template. |
| `--region` | No | REGION | Destination region. Defaults to `AWS_REGION` / `AWS_DEFAULT_REGION`. |
| `--parameters` | No | KEY=VALUE … | Template parameter values. Only parameters referenced by IAM policies are required. |
| `--template-configuration-file` | No | FILE.json | Parameter values file. Accepts CodePipeline (`{"Parameters": {...}}`), CloudFormation (`[{"ParameterKey":...,"ParameterValue":...}]`), or `["Key=Value", ...]`. `--parameters` overrides matching keys. |
| `--profile` | No | PROFILE | Named AWS profile for API calls. |
| `--enable-logging` | No | — | Log output to stdout. |
| `--allow-dynamic-ref-without-version` | No | — | Allow dynamic SSM references without a version number. |
| `--exclude-resource-types` | No | `AWS::SERVICE::RESOURCE,…` | Comma-separated CloudFormation resource types to skip. |

## validate

Adds, beyond the common flags:

| Flag | Required | Value | Description |
|---|---|---|---|
| `--ignore-finding` | No | `CODE,RESOURCE,RESOURCE.CODE` | Comma-separated findings to ignore (by code, resource, or both). |
| `--treat-finding-type-as-blocking` | No | `ERROR,SECURITY_WARNING,WARNING,SUGGESTION,NONE` | Which finding types block. Default `ERROR,SECURITY_WARNING`. `NONE` ignores all. |
| `--allow-external-principals` | No | `ACCOUNT,ARN` | External principals to ignore. 12-digit account ID, federated user, ARN, or `*` for anonymous. |

## check-no-new-access

| Flag | Required | Value | Description |
|---|---|---|---|
| `--reference-policy` | Yes | FILE.json | Reference policy for the permissions comparison. |
| `--reference-policy-type` | Yes | `identity` \| `resource` | Type of both the analyzed and reference policy. |
| `--ignore-finding` | No | `CODE,RESOURCE,RESOURCE.CODE` | Findings to ignore. |
| `--treat-findings-as-non-blocking` | No | — | When set, exit 0 regardless of findings. |

## check-access-not-granted

| Flag | Required | Value | Description |
|---|---|---|---|
| `--actions` | At least one of actions/resources | `ACTION,ACTION,…` | Actions that must not be granted. |
| `--resources` | At least one of actions/resources | `ARN,ARN,…` | Resource ARNs that must not be granted (max 100). |
| `--ignore-finding` | No | `CODE,RESOURCE,RESOURCE.CODE` | Findings to ignore. |
| `--treat-findings-as-non-blocking` | No | — | When set, exit 0 regardless of findings. |

If both actions and resources are given, the check tests whether access is
granted to those actions **on** those resources.

## check-no-public-access

| Flag | Required | Value | Description |
|---|---|---|---|
| `--ignore-finding` | No | `CODE,RESOURCE,RESOURCE.CODE` | Findings to ignore. |
| `--treat-findings-as-non-blocking` | No | — | When set, exit 0 regardless of findings. |

Evaluates resource-based policies only. See the "Scoping each check to its own
target" section of SKILL.md for the supported resource types.

## parse

Common flags only (no `--ignore-finding`, no blocking flags). Prints the
resolved policies as JSON and makes no Access Analyzer call. Useful for
troubleshooting intrinsic-function evaluation.

## Output and exit codes

Every check writes JSON of the form:

```json
{
  "BlockingFindings": [
    {
      "findingType": "SECURITY_WARNING",
      "code": "...",
      "message": "...",
      "resourceName": "...",
      "policyName": "...",
      "details": { }
    }
  ],
  "NonBlockingFindings": []
}
```

Exit code `0` = no blocking findings; `2` = at least one blocking finding. Gate
CI on the exit code.
