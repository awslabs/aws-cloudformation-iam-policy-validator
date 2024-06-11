## IAM Policy Validator for AWS CloudFormation

A command line tool that takes a CloudFormation template, parses the IAM policies attached to IAM roles, users, groups, and resources then runs them through IAM Access Analyzer for basic policy validation checks and for custom policy checks. Note that a charge is associated with each custom policy check. For more details about pricing, see [IAM Access Analyzer pricing](https://aws.amazon.com/iam/access-analyzer/pricing/).

### Getting Started

Installation:

Python 3.6+ is supported.

```
pip install cfn-policy-validator
```
Basic usage:
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1
```

Interactive workshop that walks through use of the cfn-policy-validator tool in a CI/CD pipeline: 
https://workshops.aws/card/Integrating%20IAM%20Access%20Analyzer

### Why do I need the IAM Policy Validator for AWS CloudFormation?

The cfn-policy-validator is designed to prevent the deployment of unwanted IAM identity-based and resource-based policies to your AWS environment.

CloudFormation templates commonly use [intrinsic functions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html) in templates that create least privilege IAM policies.  Take a look at the template below which creates an SQS queue with an attached SQS queue policy.

```json
{
  "Resources": {
    "MyQueue": {
      "Type": "AWS::SQS::Queue"
    },
    "MyQueuePolicy": {
      "Type": "AWS::SQS::QueuePolicy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [{
              "Action": [
                "sqs:SendMessage",
                "sqs:ReceiveMessage"
              ],
              "Effect": "Allow",
              "Resource": {
                "Fn::GetAtt": ["MyQueue", "Arn"]
              },
              "Principal": "*"
            }]
        },
        "Queues": [{"Ref": "MyQueue"}]
      }
    }
  }
}
```

Extracting the queue policy from this template as is would not give you a valid IAM policy.  The line `Fn:GetAtt: ["MyQueue", "Arn"]` is not valid IAM policy syntax - this is syntax specific to CloudFormation. The IAM Policy Validator for AWS CloudFormation (cfn-policy-validator) evaluates these intrinsic functions, like Fn:GetAtt, substituting similar or identical values to what you will get when you deploy the template.  This allows it to extract the IAM policies from the template and send them to IAM Access Analyzer, which validates the policies against checks for best practices, external access, and your custom security standard. 

The cfn-policy-validator returns a non-zero exit code when findings in IAM policies are detected and is designed to be run in a CI/CD pipeline to prevent the deployment of unwanted IAM policies to your AWS environment.


### Available Commands

**validate**

```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1
```

Parses IAM identity-based and resource-based policies from AWS CloudFormation templates and evaluated CloudFormation intrinsic functions and pseudo parameters. Then runs the policies through IAM Access Analyzer for validation. Returns the findings from validation in JSON format.
Exits with a non-zero error code if any findings categorized as blocking are found in your template.  Exits with an error code of zero if all findings are non-blocking or there are no findings.


| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --template-path | Yes | FILE_NAME | The path to the CloudFormation template. |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --parameters | | KEY=VALUE [KEY=VALUE ...] | Keys and values for CloudFormation template parameters.  Only parameters that are referenced by IAM policies in the template are required. |
| --template-configuration-file | | FILE_PATH.json | A JSON formatted file that specifies template parameter values, a stack policy, and tags. Only parameters are used from this file.  Everything else is ignored. Identical values passed in the --parameters flag override parameters in this file. See CloudFormation documentation for file format: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --treat-finding-type-as-blocking | | ERROR,SECURITY_WARNING,WARNING,SUGGESTION,NONE | Specify which finding types should be treated as blocking. Other finding types are treated as nonblocking.  If the tool detects any blocking finding types, it will exit with a non-zero exit code.  If all findings are nonblocking or there are no findings, the tool exits with an exit code of 0.  Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated list of finding types that should be blocking. Pass "NONE" to ignore all findings. |
| --allow-external-principals | | ACCOUNT,ARN | A comma separated list of external principals that should be ignored.  Specify as a comma separated list of a 12 digit AWS account ID, a federated web identity user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. (e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com) |
| --allow-dynamic-ref-without-version | | | Override the default behavior and allow dynamic SSM references without version numbers.  The version number ensures that the SSM parameter value that was validated is the one that is deployed. |
| --exclude-resource-types | | AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE | List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket |

**check-no-new-access**

```bash
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity
```

Parses IAM identity-based and resource-based policies from AWS CloudFormation templates and evaluated CloudFormation intrinsic functions and pseudo parameters. Then runs the policies through IAM Access Analyzer for a custom check against a reference policy. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on new access, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings. You can find examples for reference policies and learn how to set up and run a custom policy check for new access in the [IAM Access Analyzer custom policy checks samples](https://github.com/aws-samples/iam-access-analyzer-custom-policy-check-samples) repository on GitHub.


| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --template-path | Yes | FILE_NAME | The path to the CloudFormation template. |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --parameters | | KEY=VALUE [KEY=VALUE ...] | Keys and values for CloudFormation template parameters.  Only parameters that are referenced by IAM policies in the template are required. |
| --template-configuration-file | | FILE_PATH.json | A JSON formatted file that specifies template parameter values, a stack policy, and tags. Only parameters are used from this file.  Everything else is ignored. Identical values passed in the --parameters flag override parameters in this file. See CloudFormation documentation for file format: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --reference-policy | Yes | FILE_PATH.json | A JSON formatted file that specifies the path to the reference policy that is used for a permissions comparison.   |
| --reference-policy-type | Yes | IDENTITY or RESOURCE | The policy type associated with the IAM policy under analysis and the reference policy.  |
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --allow-dynamic-ref-without-version | | | Override the default behavior and allow dynamic SSM references without version numbers.  The version number ensures that the SSM parameter value that was validated is the one that is deployed. |
| --exclude-resource-types | | AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE | List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket |

**check-access-not-granted**
```bash
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret"
```

Parses IAM identity-based and resource-based policies from AWS CloudFormation templates. Then runs the policies through IAM Access Analyzer for a custom check against a list of IAM actions and/or resource ARNs. If both actions and resources are provided, a custom check will be run to determine whether access is granted to allow the specified actions on the specified resources. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on access granted to at least one of the listed IAM actions and/or resources, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --template-path | Yes | FILE_NAME | The path to the CloudFormation template. |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --parameters | | KEY=VALUE [KEY=VALUE ...] | Keys and values for CloudFormation template parameters.  Only parameters that are referenced by IAM policies in the template are required. |
| --template-configuration-file | | FILE_PATH.json | A JSON formatted file that specifies template parameter values, a stack policy, and tags. Only parameters are used from this file.  Everything else is ignored. Identical values passed in the --parameters flag override parameters in this file. See CloudFormation documentation for file format: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --actions | Yes | ACTION,ACTION,ACTION | List of comma-separated actions. |
| -- resources | At least one of actions or resources is required. | RESOURCE,RESOURCE,RESOURCE | List of comma-separated resource ARNs, maximum 100 resources ARNs. |
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --allow-dynamic-ref-without-version | | | Override the default behavior and allow dynamic SSM references without version numbers.  The version number ensures that the SSM parameter value that was validated is the one that is deployed. |
| --exclude-resource-types | | AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE | List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket |

**check-no-public-access**
```bash
cfn-policy-validator check-no-public-access --template-path ./my-template.json --region us-east-1
```

Parses resource-based policies from AWS CloudFormation templates. Then runs the policies through IAM Access Analyzer for a custom check for public access to resources. Returns the findings from the custom check in JSON format. Exits with a non-zero error code if any findings categorized as blocking, based on whether public access is granted to at least one of the resources, are found in your template. Exits with an error code of zero if all findings are non-blocking or there are no findings.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --template-path | Yes | FILE_NAME | The path to the CloudFormation template. |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --parameters | | KEY=VALUE [KEY=VALUE ...] | Keys and values for CloudFormation template parameters.  Only parameters that are referenced by IAM policies in the template are required. |
| --template-configuration-file | | FILE_PATH.json | A JSON formatted file that specifies template parameter values, a stack policy, and tags. Only parameters are used from this file.  Everything else is ignored. Identical values passed in the --parameters flag override parameters in this file. See CloudFormation documentation for file format: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --ignore-finding | | FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE | Allow validation failures to be ignored. Specify as a comma separated list of findings to be ignored. Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name (e.g. "MyResource"), or a combination of both separated by a period.(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").  Names of finding codes may change in IAM Access Analyzer over time.
| --treat-findings-as-non-blocking | | | When not specified, the tool detects any findings, it will exit with a non-zero exit code. When specified, the tool exits with an exit code of 0. |
| --allow-dynamic-ref-without-version | | | Override the default behavior and allow dynamic SSM references without version numbers.  The version number ensures that the SSM parameter value that was validated is the one that is deployed. |
| --exclude-resource-types | | AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE | List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket |

**parse**  

```bash
cfn-policy-validator parse --template-path ./my-template.json --region us-east-1
```

Parses IAM identity-based and resource-based policies from AWS CloudFormation templates and evaluates CloudFormation intrinsic functions and pseudo parameters.  Returns the parsed file in JSON format.  This command does not make any calls to IAM Access Analyzer.  Parse can be a useful troubleshooting tool or useful if you just want the CloudFormation function evaluation.

| Arguments | Required |  Options | Description |
| --------- | -------- | ---------| ----------- |
| --template-path | Yes | FILE_NAME | The path to the CloudFormation template. |
| --region | Yes | REGION | The destination region the resources will be deployed to. |
| --parameters | | KEY=VALUE [KEY=VALUE ...] | Keys and values for CloudFormation template parameters.  Only parameters that are referenced by IAM policies in the template are required. |
| --template-configuration-file | | FILE_PATH.json | A JSON formatted file that specifies template parameter values, a stack policy, and tags. Everything except for parameters are ignored from this file. Identical values passed in the --parameters flag override parameters in this file. See CloudFormation documentation for file format: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15
| --profile | | PROFILE | The named profile to use for AWS API calls. |
| --enable-logging | | | Enables log output to stdout |
| --allow-dynamic-ref-without-version | | | Override the default behavior and allow dynamic SSM references without version numbers.  The version number ensures that the SSM parameter value that was validated is the one that is deployed. |
| --exclude-resource-types | | AWS::SERVICE::RESOURCE, AWS::SERVICE::RESOURCE | List of comma-separated resource types. Resource types should be the same as Cloudformation template resource names such as AWS::IAM::Role, AWS::S3::Bucket |

### Supported resource-based policies

| CloudFormation Resource Type | Policy best practice checks | Access previews (check for external access) | Custom Policy Check (public access)
| ---------------------------- | :----------------: | :-----------------------------------------: | :-----------------------------------------:
| AWS::KMS::Key                | x                  | x | x |
| AWS::Lambda::Permission      | x                  | | x |
| AWS::Lambda::LayerVersionPermission | x           | | x |
| AWS::S3::BucketPolicy        | x                  | x | x |
| AWS::S3::AccessPoint         | x                  | x | x |
| AWS::S3::MultiRegionAccessPoint | x | x |
| AWS::SQS::QueuePolicy        | x                  | x | x |
| AWS::SNS::TopicPolicy        | x                  | | x |
| AWS::SecretsManager::ResourcePolicy | x           | | x |
| AWS::IAM::Role (trust policy) | x | x | x |

### Intrinsic function and Pseudo parameter support

The functions in the following list can be used within IAM identity-based or resource-based policies.  The tool only attempts to evaluate intrinsic functions within policies, so you can still use intrinsic functions not on this list elsewhere in your template.

Supported intrinsic functions
- Fn::FindInMap
- Fn::GetAtt
- Fn::ImportValue
- Fn::Join
- Fn::Select
- Fn::Split
- Fn::Sub
- Ref
- Fn::If
- Fn::Equals
- Condition
- Fn::Not
- Fn::And
- Fn::Or

Supported pseudo parameters:
- AWS::Region
- AWS::AccountId
- AWS::Partition
- AWS::StackName (returns the literal string "StackName")
- AWS::NoValue

[Dynamic SSM references](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html) are supported, but must have a version number.  This is to help ensure the same parameter that is validated is the one that is deployed.  This restriction can be overridden with the --allow-dynamic-ref-without-version argument.

SSM-Secure and SecretsManager dynamic references are not yet supported.

Notes:
- Fn::Transform (includes macros and AWS::Serverless/SAM transforms) not yet supported
- References (Ref/GetAtt) to CloudFormation modules are not yet supported
- A [condition function](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-conditions.html) may have different behavior when deployed if you use the ```Ref``` function in the condition. This is because the tool is unable to accurately provide a value for references that are not known until deployment.

### Credentials

The cfn-policy-validator should be run using credentials from the AWS account that you plan to deploy the CloudFormation template to. The tool uses boto3 to interact with your AWS account. You can use one of the following methods to specify credentials:

- Environment variables
- Shared credential file (~/.aws/credentials)
- AWS config file (~/.aws/config)
- Assume Role provider
- Instance metadata service on an Amazon EC2 instance that has an IAM role configured.

[Read more about these options](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html)

You can also specify a [named profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) using the --profile command line flag.

The principal used to execute the cfn-policy-validator requires the following permissions.

###  IAM policy required to run the IAM Policy Validator for AWS CloudFormation

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
              "iam:GetPolicy",
              "iam:GetPolicyVersion",
              "access-analyzer:ListAnalyzers",
              "access-analyzer:ValidatePolicy",
              "access-analyzer:CreateAccessPreview",
              "access-analyzer:GetAccessPreview",
              "access-analyzer:ListAccessPreviewFindings",
              "access-analyzer:CreateAnalyzer",
              "access-analyzer:CheckNoNewAccess",
              "access-analyzer:CheckAccessNotGranted",
              "access-analyzer:CheckNoPublicAccess",
              "s3:ListAllMyBuckets",
              "cloudformation:ListExports",
              "ssm:GetParameter"
            ],
            "Resource": "*"
        },
        {
          "Effect": "Allow",
          "Action": "iam:CreateServiceLinkedRole",
          "Resource": "*",
          "Condition": {
            "StringEquals": {
              "iam:AWSServiceName": "access-analyzer.amazonaws.com"
            }
          }
        } 
    ]
}
```

| Action Name| Justification |
| ---------- | ------------- |
| iam:GetPolicy | Read IAM managed policies from your environment if included in an IAM user, role, or group. |
| iam:GetPolicyVersion | Read IAM managed policies from your environment if included in an IAM user, role, or group. |
| access-analyzer:ListAnalyzers | Detect if there is an existing analyzer in your account.  |
| access-analyzer:ValidatePolicy | Called for each policy to validate against IAM policy best practices. |
| access-analyzer:CreateAccessPreview | Generate access previews. |
| access-analyzer:GetAccessPreview | Retrieve generated access previews.  |
| access-analyzer:ListAccessPreviewFindings | Retrieve findings from access preview. |
| access-analyzer:CreateAnalyzer | (Optional) Create an analyzer if one does not already exist in the account.  Optional if account has analyzer already. |
| access-analyzer:CheckNoNewAccess | Called for each policy to validate against a reference policy to compare permissions. |
| access-analyzer:CheckAccessNotGranted | Called for each policy to validate that it does not grant access to a list of IAM actions, considered as critical permissions, provided as input. |
| access-analyzer:CheckNoPublicAccess | Called for each policy to validate that it does not grant public access to supported resource types. |
| iam:CreateServiceLinkedRole | (Optional) Create a service linked role if an analyzer must be created in account.  Optional if account has analyzer already. |
| s3:ListAllMyBuckets | Retrieve the canonical ID of the account. |
| cloudformation:ListExports | List CloudFormation exports to be used with Fn::ImportValue  |
| ssm:GetParameter | Resolution of dynamic ssm parameter references |

## FAQ

### How does the validator deal with intrinsic functions within policies?

One of the biggest challenges of parsing IAM policies within a CloudFormation template is dealing with Ref and Fn::GetAtt references to other resources within the template. These references commonly return ARNs whose exact value is unknown until the resource is created. 

The tool deals with this by autogenerating appropriate ARNs for the referenced resource.  The autogenerated ARN will have a valid ARN structure for that resource and a randomly generated name.  The tool can do this and still provide valid IAM finding results because the structure of the ARN is what is important, not the value of the resource name.

The tool maps AWS CloudFormation resource types to ARN patterns and does token replacement on the patterns.  The mapping can be seen in cfn_policy_validator/parsers/utils/cfn_to_arn_map.json

### What happens if I don't have an existing analyzer in the account?

The cfn-policy-validator will create an analyzer for you if you don't have one in your account.  Analyzers for access previews are per account and not per organization.

### Why does my S3 bucket policy not report a finding even though the policy makes it publicly accessible?

Access previews take in the entire context of your AWS account, not just the S3 bucket policy.  If your account level block public access flag is enabled, IAM Access Analyzer correctly classifies your bucket as not publicly accessible and no findings are reported.

### Why does my SecretsManager Secret not report a finding even though the policy makes it publicly accessible?

Creating an access preview for a SecretsManager Secret requires a KMSKeyId.  The cfn-policy-validator does not yet support parsing the KMS Key from the environment.  When no KMSKeyId is supplied, the CreateAccessPreview API uses the default CMK in the account which is not externally accessible.

### What is the distinction between Access Previews and CheckNoPublicAccess?

CheckNoPublicAccess custom policy checks differ from Access Previews because CheckNoPublicAccess checks do not require any account or external access analyzer context. Note that a charge is associated with each custom policy check.


### Examples

Basic validate call
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1
```

Basic custom policy check calls
```bash 
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret"
```

Basic parse call
```bash
cfn-policy-validator parse --template-path ./my-template.json --region us-east-1
```

Validate with parameters
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --parameters MyParameter1=MyValue1 MyParameter2=MyValue2
```

Custom policy check with parameters
```bash 
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity --parameters MyParameter1=MyValue1 MyParameter2=MyValue2
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret" --parameters MyParameter1=MyValue1 MyParameter2=MyValue2
```

Validate with template configuration file
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --template-configuration-file ./template-configuration-file.json
```

Validate and ignore findings for a specific finding code for all resources
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --ignore-finding PASS_ROLE_WITH_STAR_IN_RESOURCE
```

Validate and ignore findings for a specific resource
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --ignore-finding MyResource1
```

Custom policy check and ignore findings for a specific resource
```bash
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity --ignore-findings MyResource1
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret" --ignore-findings MyResource1
```

Custom policy check and ignore findings for a specific resource
```bash
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity --ignore-findings MyResource1
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret" --ignore-findings MyResource1
```

Validate and ignore all findings for `MyResource1` and finding code `PASS_ROLE_WITH_STAR_IN_RESOURCE` for all resources
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --ignore-finding MyResource1,PASS_ROLE_WITH_STAR_IN_RESOURCE
```

Validate and treat warnings as blocking in addition to ERROR and SECURITY_WARNING (defaults)
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --treat-finding-type-as-blocking ERROR,SECURITY_WARNING,WARNING
```

Custom policy check and treat findings as non-blocking
```bash
cfn-policy-validator check-no-new-access --template-path ./my-template.json --region us-east-1 --reference-policy ./my-reference-policy.json --reference-policy-type identity --treat-findings-as-non-blocking
cfn-policy-validator check-access-not-granted --template-path ./my-template.json --region us-east-1 --actions "secretsmanager:DeleteSecret" --ignore-findings MyResource1 --treat-findings-as-non-blocking
```

Validate and ignore findings from account 123456789123 for cross account access
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --allow-external-principals 123456789123
```

Validate and ignore findings from a role in another account
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --allow-external-principals arn:aws:iam::111111111111:role/MyOtherRole
```

Validate and allow anonymous access (this is usually not what you want, make sure you have a good reason to allow anonymous access)
```bash
cfn-policy-validator validate --template-path ./my-template.json --region us-east-1 --allow-external-principals "*"
```