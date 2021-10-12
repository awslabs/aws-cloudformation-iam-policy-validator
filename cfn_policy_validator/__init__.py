"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import io
import logging

from cfn_policy_validator import client, parameters
from cfn_policy_validator.application_error import SchemaValidationError, ApplicationError
from cfn_policy_validator.argument_actions import parse_findings_to_ignore, parse_allow_external_principals
from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.parameters import validate_finding_types
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.parsers.output import Output
from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.validation import validator
from cfn_policy_validator.validation.reporter import default_finding_types_that_are_blocking

LOGGER = logging.getLogger('cfn-policy-validator')


def validate(template_body,
             region,
             account_id,
             partition,
             template_parameters=None,
             ignore_finding=None,
             treat_as_blocking=default_finding_types_that_are_blocking,
             allowed_external_principals=None):
    """
    Parses a CloudFormation template and runs it through IAM Access Analyzer for validation.
    @param template_body: String containing the body of the CloudFormation template.
    @param region: The region that the CloudFormation template will be deployed to.
    @param account_id: The AWS account ID that the CloudFormation template will be deployed to.
    @param partition: The AWS partition that the CloudFormation template will be deployed to.
    @param template_parameters:  A key: value dictionary of parameters that will be passed to the CloudFormation
        template when deployed.  e.g. { 'Parameter1Name': 'Parameter1Value', 'Parameter2Name': 'Parameter2Value' }
    @param ignore_finding: Allow validation failures to be ignored. Specify as a list of findings to be ignored.
        Can be individual finding codes (e.g. "PASS_ROLE_WITH_STAR_IN_RESOURCE"), a specific resource name
        (e.g. "MyResource"), or a combination of both separated by a period.
        (e.g. "MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE").
        Example: ["MyResource", "PASS_ROLE_WITH_STAR_IN_RESOURCE"]
    @param treat_as_blocking: Specify which finding types should be treated as errors. Other finding types are treated
        as warnings. Defaults to "ERROR" and "SECURITY_WARNING". Specify as a list of finding types that should be
        blocking. Possible values are "ERROR", "SECURITY_WARNING", "SUGGESTION", and "WARNING".  Pass "NONE" to ignore
        all errors.
        Example: ["ERROR", "SECURITY_WARNING", "WARNING"]
    @param allowed_external_principals: A list of external principals that should be ignored.  Specify as a list of
        a 12 digit AWS account ID, a federated web identity user, a federated SAML user, or an ARN. Specify "*"
        to allow anonymous access.
        Example: ["123456789123","arn:aws:iam::111111111111:role/MyOtherRole","graph.facebook.com"]
    @return: A JSON formatted object containing findings classified as either blocking or non-blocking from IAM Access
        Analyzer
    """

    # this is done to avoid mutable default arguments as described here:
    # https://docs.python-guide.org/writing/gotchas/
    template_parameters = {} if template_parameters is None else template_parameters

    # validate input parameters
    ignore_finding = parse_findings_to_ignore(ignore_finding)
    allowed_external_principals = parse_allow_external_principals(allowed_external_principals)
    treat_as_blocking = validate_finding_types(treat_as_blocking)

    return _inner_validate(template_body, region, account_id, partition,
                           template_parameters, ignore_finding, treat_as_blocking, allowed_external_principals)


def _inner_validate(template_body, region, account_id, partition,
                    template_parameters, ignore_finding, treat_as_blocking, allowed_external_principals):
    account_config = AccountConfig(partition, region, account_id)
    template = _parse_template(template_body, account_config, template_parameters)
    parser_output = _parse_template_output(template, account_config)
    report = validator.validate(parser_output, ignore_finding, treat_as_blocking, allowed_external_principals)

    return report.to_json()


def parse(template_body,
          region,
          account_id,
          partition,
          template_parameters=None):
    """
        Parses a CloudFormation template.
        @param template_body: String containing the body of the CloudFormation template.
        @param region: The region that the CloudFormation template will be deployed to.
        @param account_id: The AWS account ID that the CloudFormation template will be deployed to.
        @param partition: The AWS partition that the CloudFormation template will be deployed to.
        @param template_parameters:  A key: value dictionary of parameters that will be passed to the CloudFormation
            template when deployed.  e.g. { 'Parameter1Name': 'Parameter1Value', 'Parameter2Name': 'Parameter2Value' }
        @return: A JSON formatted object containing findings classified as either blocking or non-blocking from IAM Access
            Analyzer
        """
    template_parameters = {} if template_parameters is None else template_parameters

    # TODO: deal with logging
    return _inner_parse(template_body, region, account_id, partition, template_parameters)


def _inner_parse(template_body, region, account_id, partition, template_parameters):
    account_config = AccountConfig(partition, region, account_id)
    template = _parse_template(template_body, account_config, template_parameters)
    parser_output = _parse_template_output(template, account_config)

    return parser_output.to_json()


def _parse_template(template_body, account_config, template_parameters):
    stream = io.StringIO(template_body)

    try:
        template = cfn_loader.load(stream, account_config, template_parameters)
    except SchemaValidationError:
        logging.exception('Unable to parse CloudFormation template.  Invalid CloudFormation schema detected.')
        raise ApplicationError('Unable to parse CloudFormation template.  Invalid CloudFormation schema detected.')
    except Exception:
        logging.exception('Unable to parse CloudFormation template.  Invalid YAML or JSON detected.')
        raise ApplicationError('Unable to parse CloudFormation template.  Invalid YAML or JSON detected.')

    return template


def _parse_template_file(file_path, account_config, template_parameters):
    try:
        with open(file_path, 'r') as stream:
            try:
                template = cfn_loader.load(stream, account_config, template_parameters)
            except SchemaValidationError:
                logging.exception('Unable to parse CloudFormation template.  Invalid CloudFormation schema detected.')
                raise ApplicationError('Unable to parse CloudFormation template.  Invalid CloudFormation schema detected.')
            except Exception:
                logging.exception('Unable to parse CloudFormation template.  Invalid YAML or JSON detected.')
                raise ApplicationError('Unable to parse CloudFormation template.  Invalid YAML or JSON detected.')
    except FileNotFoundError:
        raise ApplicationError(f'CloudFormation template not found: {file_path}')

    return template


def _parse_template_output(template, account_config):
    output = Output(account_config)
    output.Roles, output.Users, output.Groups, output.PermissionSets, output.OrphanedPolicies = \
        IdentityParser.parse(template, account_config)
    output.Resources = ResourceParser.parse(template, account_config)

    return output
