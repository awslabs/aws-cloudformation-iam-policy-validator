"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import argparse
import logging
import sys
import traceback
from cfn_policy_validator.validation import policy_analysis

from cfn_policy_validator.validation import validator
from cfn_policy_validator.version import __version__
from cfn_policy_validator import parameters, client, AccountConfig, \
    _parse_template_file, _parse_template_output, _load_json_file
from cfn_policy_validator.validation.reporter import default_finding_types_that_are_blocking
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.argument_actions import DictionaryArgument, \
    ParseFindingsToIgnoreFromCLI, ParseAllowExternalPrincipalsFromCLI, \
    ParseListFromCLI
from cfn_policy_validator.logger import configure_logging
from cfn_policy_validator.parameters import validate_region, \
    validate_finding_types_from_cli, \
    validate_credentials

LOGGER = logging.getLogger('cfn-policy-validator')


def get_parser_output(arguments):
    LOGGER.info(f'Validating template {arguments.template_path}')
    account_id, partition = client.get_account_and_partition(arguments.region)
    account_config = AccountConfig(partition, arguments.region, account_id)

    template = _parse_template_file(arguments.template_path, account_config, arguments.parameters, arguments.allow_dynamic_ref_without_version)
    return _parse_template_output(template, account_config, set(arguments.exclude_resource_type))

# consumable when running as CLI
def validate_from_cli(arguments):
    LOGGER.info(f'Validating template {arguments.template_path}')
    report = validator.validate(get_parser_output(arguments), arguments.ignore_finding, arguments.treat_as_blocking, arguments.allowed_external_principals)

    report.print()
    if report.has_blocking_findings():
        exit(2)
    else:
        exit(0)

# consumable when running as CLI
def compare_from_cli(arguments):
    LOGGER.info(f'Checking that template {arguments.template_path} is less permissive than reference policy {arguments.reference_policy}')
    reference_policy = _load_json_file(arguments.reference_policy)
    report = policy_analysis.compare(get_parser_output(arguments), reference_policy, arguments.reference_policy_type, arguments.ignore_finding, arguments.findings_are_blocking)

    report.print()
    if report.has_blocking_findings():
        exit(2)
    else:
        exit(0)


# consumable when running as CLI
def check_access_from_cli(arguments):
    if not arguments.actions and not arguments.resources:
      raise ApplicationError("At least one of --actions or --resources must be specified.")
    else:
      report = policy_analysis.check_access(get_parser_output(arguments), arguments.ignore_finding, arguments.findings_are_blocking, arguments.actions, arguments.resources)
      report.print()
      if report.has_blocking_findings():
        exit(2)
      else:
        exit(0)


# consumable when running as CLI
def check_no_public_access_from_cli(arguments):
    LOGGER.info(f'Checking that template {arguments.template_path} does not grant public access to resources.')
    report = policy_analysis.check_no_public_access(get_parser_output(arguments), arguments.ignore_finding, arguments.findings_are_blocking)

    report.print()
    if report.has_blocking_findings():
        exit(2)
    else:
        exit(0)


# consumable when running as CLI
def parse_from_cli(arguments):
    LOGGER.info(f'Parsing template {arguments.template_path}')
    account_id, partition = client.get_account_and_partition(arguments.region)
    account_config = AccountConfig(partition, arguments.region, account_id)

    template = _parse_template_file(arguments.template_path, account_config, arguments.parameters, arguments.allow_dynamic_ref_without_version)
    parser_output = _parse_template_output(template, account_config, set(arguments.exclude_resource_type))

    parser_output.print()
    exit(0)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--template-path', metavar="TEMPLATE_PATH", dest="template_path", required=True,
                        help='The path to the CloudFormation template.')

    parent_parser.add_argument('--region', dest="region", required=True, type=validate_region,
                        help="The region the resources will be deployed to.")

    parent_parser.add_argument('--parameters', action=DictionaryArgument, nargs="+", metavar="KEY=VALUE", dest="parameters",
                        help='Parameter key and value in the format -p Key1=Value1 Key2=Value2.  Only parameters'
                             ' that are referenced by IAM policies are required.', default={})

    parent_parser.add_argument('--template-configuration-file', metavar='FILE_PATH.json', dest="template_configuration_file",
                               help="A JSON formatted file that specifies template parameter values, a stack policy, and tags."
                                    "Everything but parameters are ignored from this file. Identical values passed in "
                                    "the --parameters flag override parameters in this file\n"
                                    "See CloudFormation documentation on format for this file: "
                                    "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15")

    parent_parser.add_argument('--profile', help='The named profile to use for AWS API calls.')

    parent_parser.add_argument('--enable-logging', help='Enable detailed logging.', default=False,
                               action='store_true')

    parent_parser.add_argument('--allow-dynamic-ref-without-version', help='Allow the retrieval of dynamic references without specifying a version number.  Specifying a version number'
                                ' helps ensure that the reference does not change between validation and deployment. Allowing dynamic references without versions would make it'
                                ' possible for the template you deploy to be different from the one that was validated.', default=False, action='store_true')

    parent_parser.add_argument('--exclude-resource-types', dest="exclude_resource_type", action=ParseListFromCLI, default=[],
                        help='Resource types to exclude from parsing. Specify as a comma separated list of CloudFormation resource types. '
                        'Please see README for full list of possible types.')

    parser = argparse.ArgumentParser(description='Parses IAM identity-based and resource-based policies from AWS CloudFormation templates.')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)

    subparsers = parser.add_subparsers(dest='{parse,validate,check-no-new-access,check-access-not-granted,check-no-public-access}')
    subparsers.required = True

    # parse command
    parse_parser = subparsers.add_parser('parse', help='Replaces intrinsic and pseudo functions in an AWS CloudFormation '
                                                       'template and returns a JSON formatted list of IAM policies and '
                                                       'their attached resources.', parents=[parent_parser])
    parse_parser.set_defaults(func=parse_from_cli)

    # validate command
    validate_parser = subparsers.add_parser('validate', help='Parses IAM identity-based and resource-based policies from AWS CloudFormation templates '
                                                           'and runs them through IAM Access Analyzer for validation.  Returns the findings from '
                                                           'validation in JSON format.', parents=[parent_parser])
    validate_parser.set_defaults(func=validate_from_cli)

    validate_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                 help='Allow validation failures to be ignored.\n'
                             'Specify as a comma separated list of findings to be ignored. Can be individual '
                             'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                             '(e.g. "MyResource"), or a combination of both separated by a period.'
                             '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                 action=ParseFindingsToIgnoreFromCLI)

    validate_parser.add_argument('--treat-finding-type-as-blocking', dest="treat_as_blocking", metavar="ERROR,SECURITY_WARNING",
                                 help='Specify which finding types should be treated as blocking. Other finding types are treated '
                                     'as non-blocking. Defaults to "ERROR" and "SECURITY_WARNING". Specify as a comma separated '
                                     'list of finding types that should be blocking.  Possible values are "ERROR", '
                                     '"SECURITY_WARNING", "SUGGESTION", and "WARNING".  Pass "NONE" to ignore all errors.',
                                 default=default_finding_types_that_are_blocking, type=validate_finding_types_from_cli)

    validate_parser.add_argument('--allow-external-principals', dest='allowed_external_principals', metavar="ACCOUNT,ARN",
                                 help='A comma separated list of external principals that should be ignored.  Specify as '
                                     'a comma separated list of a 12 digit AWS account ID, a federated web identity '
                                     'user, a federated SAML user, or an ARN. Specify "*" to allow anonymous access. '
                                     '(e.g. 123456789123,arn:aws:iam::111111111111:role/MyOtherRole,graph.facebook.com)',
                                 action=ParseAllowExternalPrincipalsFromCLI)
    
    def add_policy_analysis_subparsers():
        # check-no-new-access command
        compare_parser = subparsers.add_parser('check-no-new-access', help='Parses IAM identity-based and resource-based policies from AWS CloudFormation templates '
                                                            'and runs them through IAM Access Analyzer for comparison with a reference policy.  Returns the response '
                                                            'in JSON format.', parents=[parent_parser])
        compare_parser.set_defaults(func=compare_from_cli)

        compare_parser.add_argument('--reference-policy', dest="reference_policy", required=True,
                                    help='Reference policy to be compared to.\n')

        compare_parser.add_argument('--reference-policy-type', dest="reference_policy_type", required=True,
                                    type=str, help='The type of the reference policy (identity or resource)')

        
        compare_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        compare_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')
        
        # check-access-not-granted command
        check_access_parser = subparsers.add_parser('check-access-not-granted', help='Parses IAM identity-based and resource-based policies from'
                                                              'AWS CloudFormation templates and runs them through IAM Access Analyzer to check '
                                                              'that access to a list of actions and/or resources is not granted. Returns the '
                                                              'response in JSON format.', parents=[parent_parser])
        check_access_parser.set_defaults(func=check_access_from_cli)


        check_access_parser.add_argument('--resources', dest="resources",
                                         help= 'Resources that policies should not grant access to. '
                                               'Specify as a comma-separated list of resource ARNs to be checked. '
                                               'A maximum of 100 resources can be specified for a single request. '
                                               'The tool will not make multiple requests if you provide more resources than the allowed quota. '
                                               'At least one of --actions or --resources must be specified.', action=ParseListFromCLI)

        check_access_parser.add_argument('--actions', dest="actions",
                                    help= 'Actions that policies should not grant. '
                                          'Specify as a comma separated list of actions to be checked. '
                                          'A maximum of 100 actions can be specified for a single request. '
                                          'The tool will make multiple requests if you provide more actions than the allowed quota. '
                                          'At least one of --actions or --resources must be specified.', action=ParseListFromCLI)

        check_access_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        check_access_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')
        # check-no-public-access command
        check_no_public_access_parser = subparsers.add_parser('check-no-public-access', help='Parses resource-based policies from AWS CloudFormation templates '
                                                            'and runs them through IAM Access Analyzer to check that public access to resources of supported types is not granted.  Returns the response '
                                                            'in JSON format.', parents=[parent_parser])
        check_no_public_access_parser.set_defaults(func=check_no_public_access_from_cli)
        
        check_no_public_access_parser.add_argument('--ignore-finding', dest="ignore_finding", metavar='FINDING_CODE,RESOURCE_NAME,RESOURCE_NAME.FINDING_CODE',
                                    help='Allow findings to be ignored.\n'
                                        'Specify as a comma separated list of findings to be ignored. Can be individual '
                                        'finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name '
                                        '(e.g. "MyResource"), or a combination of both separated by a period.'
                                        '(e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").',
                                        action=ParseFindingsToIgnoreFromCLI)
        check_no_public_access_parser.add_argument('--treat-findings-as-non-blocking', dest="findings_are_blocking", 
                                    help='If set, all findings will be treated as non-blocking',
                                    default=True, action='store_false')
    add_policy_analysis_subparsers()

    args = parser.parse_args(args)

    try:
        client.set_profile(args.profile)
        validate_credentials(args.region)

        configure_logging(args.enable_logging)
        args.parameters = parameters.merge(args.parameters, args.template_configuration_file)
        args.func(args)
    except ApplicationError as e:
        print(f'ERROR: {str(e)}', file=sys.stderr)
        exit(1)
    except Exception as e:
        traceback.print_exc()
        print(f'ERROR: Unexpected error occurred. {str(e)}', file=sys.stderr)
        exit(1)


if __name__ == "__main__":
    main()
