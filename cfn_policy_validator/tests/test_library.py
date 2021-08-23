"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest
from argparse import ArgumentTypeError
from unittest.mock import patch, ANY

import cfn_policy_validator
from cfn_policy_validator import parse, validate
from cfn_policy_validator.tests import ParsingTest, account_config, ValidationTest
from cfn_policy_validator.tests.utils import ignore_warnings
from cfn_policy_validator.validation.reporter import ResourceAndCodeFindingToIgnore, AllowedExternalPrincipal, \
    ResourceOrCodeFindingToIgnore, AllowedExternalArn, default_finding_types_that_are_blocking

this_files_directory = os.path.dirname(os.path.realpath(__file__))


# this test runs through a parse happy path
class WhenParsingATemplateAsLibrary(ParsingTest):
    def setUp(self):
        # ignore ResourceWarnings to avoid output being polluted by them
        # unittest resets this after every test, so it needs to go in setUp
        ignore_warnings()

    def test_returns_parser_output_as_json(self):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
        with open(json_file_path, 'r') as f:
            file_body = json.dumps(json.load(f))

        self.output = parse(file_body,
                            account_config.region,
                            account_config.account_id,
                            account_config.partition,
                            {
                                'CodestarConnectionArn': 'fakeArn',
                                'EnvironmentName': 'prod'
                            })

        self.assertEqual(account_config.region, self.output['Region'])
        self.assertEqual(account_config.account_id, self.output['Account'])
        self.assertEqual(account_config.partition, self.output['Partition'])

        roles = self.output['Roles']
        self.assertEqual(2, len(roles))
        self.assert_role(role_name='CodeBuildServiceRole', role_path='/', number_of_policies=2)
        self.assert_role(role_name='CodePipelineServiceRole', role_path='/', number_of_policies=1)

        users = self.output['Users']
        self.assertEqual(1, len(users))
        self.assert_user(user_name='MyIAMUser', user_path='/my-test-path/', number_of_policies=2)

        groups = self.output['Groups']
        self.assertEqual(1, len(groups))
        self.assert_group(group_name='MyIAMGroup', group_path='/my-test-group-path/', number_of_policies=2)

        resources = self.output['Resources']
        self.assertEqual(3, len(resources))
        self.assert_resource(resource_name='MyQueue', resource_type='AWS::SQS::Queue')
        self.assert_resource(resource_name='prod-app-artifacts', resource_type='AWS::S3::Bucket')
        self.assert_resource(resource_name='MySecret', resource_type='AWS::SecretsManager::Secret')

        policies = self.output['OrphanedPolicies']
        self.assertEqual(1, len(policies))
        self.assert_orphaned_policy(policy_name='MyOrphanedPolicy')


class WhenValidatingATemplateAsLibrary(ValidationTest):
    def setUp(self):
        ignore_warnings()

    def test_returns_json(self):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
        with open(json_file_path, 'r') as f:
            file_body = json.dumps(json.load(f))

        self.output = validate(
            file_body,
            account_config.region,
            account_config.account_id,
            account_config.partition,
            {
                'CodestarConnectionArn': 'fakeArn',
                'EnvironmentName': 'prod'
            },
            ['MyIAMUser.PASS_ROLE_WITH_STAR_IN_RESOURCE'],
            ['ERROR', 'SECURITY_WARNING'],
            ['123456789123']
        )

        self.assertEqual(2, len(self.output['NonBlockingFindings']))
        self.assert_warning('WARNING', 'MISSING_VERSION', 'prod-app-artifacts', 'BucketPolicy')
        self.assert_warning('WARNING', 'MISSING_VERSION', 'MyQueue', 'QueuePolicy')

        self.assertEqual(5, len(self.output['BlockingFindings']))
        self.assert_error('ERROR', 'MISSING_ARN_FIELD', 'CodePipelineServiceRole', 'root')
        self.assert_error('ERROR', 'MISSING_PRINCIPAL', 'MyQueue', 'QueuePolicy')
        self.assert_error('SECURITY_WARNING', 'PASS_ROLE_WITH_STAR_IN_RESOURCE', 'CodePipelineServiceRole', 'root')
        self.assert_error('SECURITY_WARNING', 'PASS_ROLE_WITH_STAR_IN_RESOURCE', 'MyIAMGroup', 'root')
        self.assert_error('SECURITY_WARNING', 'EXTERNAL_PRINCIPAL', 'prod-app-artifacts', 'BucketPolicy')


class WhenParsingArgumentsForValidate(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    def assert_called_with(self, parameters=ANY, ignore_finding=ANY, treat_as_blocking=default_finding_types_that_are_blocking, allowed_external_principals=ANY):
        template_body = {}
        region = account_config.region
        account_id = account_config.account_id
        partition = account_config.partition

        self.mock.assert_called_with(template_body, region, account_id, partition, parameters,
                                     ignore_finding, treat_as_blocking, allowed_external_principals)

    def validate(self, **kwargs):
        with patch.object(cfn_policy_validator, '_inner_validate') as self.mock:
            validate({}, account_config.region, account_config.account_id, account_config.partition, **kwargs)

    def validate_with_expected_error(self, error_message, **kwargs):
        with self.assertRaises(ArgumentTypeError) as error:
            validate({}, account_config.region, account_config.account_id, account_config.partition, **kwargs)

        self.assertIn(error_message, str(error.exception))

    def test_with_no_parameters(self):
        self.validate()
        self.assert_called_with(parameters={})

    def test_called_with_parameters(self):
        self.validate(template_parameters={
            'Key1': 'Value1',
            'Key2': 'Value2'
        })
        self.assert_called_with(parameters={'Key1': 'Value1', 'Key2': 'Value2'})

    def test_ignore_finding_default_is_none(self):
        self.validate()
        self.assert_called_with(ignore_finding=None)

    def test_invalid_treat_as_blocking_value(self):
        self.validate_with_expected_error('Invalid finding type: INVALID.',
                                          treat_as_blocking=['invalid'])

    def test_treat_as_blocking_default(self):
        self.validate()
        self.assert_called_with(treat_as_blocking=['ERROR', 'SECURITY_WARNING'])

    def test_treat_as_blocking_is_upper_cased(self):
        self.validate(treat_as_blocking=['warning', 'suggestion'])
        self.assert_called_with(treat_as_blocking=['WARNING', 'SUGGESTION'])

    def test_treat_as_blocking_removes_whitespace(self):
        self.validate(treat_as_blocking=['warning  ', 'error    '])
        self.assert_called_with(treat_as_blocking=['WARNING', 'ERROR'])

    def test_ignore_finding_with_resource_parsed_to_class(self):
        self.validate(ignore_finding=['MyResource'])

        expected = ResourceOrCodeFindingToIgnore('MyResource')
        self.assert_called_with(ignore_finding=[expected])

    def test_ignore_finding_with_code_parsed_to_class(self):
        self.validate(ignore_finding=['PASS_ROLE_WITH_STAR_IN_RESOURCE'])

        expected = ResourceOrCodeFindingToIgnore('PASS_ROLE_WITH_STAR_IN_RESOURCE')
        self.assert_called_with(ignore_finding=[expected])

    def test_ignore_finding_with_code_and_resource_parsed_to_class(self):
        self.validate(ignore_finding=['MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE'])

        expected = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        self.assert_called_with(ignore_finding=[expected])

    def test_ignore_finding_with_multiple_findings_to_ignore(self):
        self.validate(ignore_finding=['MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE', 'MyResource2'])

        expected1 = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        expected2 = ResourceOrCodeFindingToIgnore('MyResource2')
        self.assert_called_with(ignore_finding=[expected1, expected2])

    def test_ignore_finding_with_extra_whitespace(self):
        self.validate(ignore_finding=['MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE', '     MyResource2'])

        expected1 = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        expected2 = ResourceOrCodeFindingToIgnore('MyResource2')
        self.assert_called_with(ignore_finding=[expected1, expected2])

    def test_allow_external_principals_with_account_id_parsed_to_class(self):
        self.validate(allowed_external_principals=['123456789123'])

        expected = AllowedExternalPrincipal('123456789123')
        self.assert_called_with(allowed_external_principals=[expected])

    def test_allow_external_principals_with_arn_parsed_to_class(self):
        self.validate(allowed_external_principals=['arn:aws:iam::123456789123:role/MyOtherRole'])

        expected = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected])

    def test_allow_external_principals_with_multiple_principals(self):
        self.validate(allowed_external_principals=['123456789123', 'arn:aws:iam::123456789123:role/MyOtherRole'])

        expected1 = AllowedExternalPrincipal('123456789123')
        expected2 = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected1, expected2])

    def test_allow_external_principals_with_extra_whitespace(self):
        self.validate(allowed_external_principals=['123456789123', '    arn:aws:iam::123456789123:role/MyOtherRole'])

        expected1 = AllowedExternalPrincipal('123456789123')
        expected2 = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected1, expected2])

    def test_allow_external_principals_with_value_that_does_not_contain_arn(self):
        # test that even values that contain the word "arn" aren't parsed as ARNs
        self.validate(allowed_external_principals=['warning'])

        expected = AllowedExternalPrincipal('warning')
        self.assert_called_with(allowed_external_principals=[expected])


class WhenParsingArgumentsForParse(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    def assert_called_with(self, parameters=ANY):
        template_body = {}
        region = account_config.region
        account_id = account_config.account_id
        partition = account_config.partition

        self.mock.assert_called_with(template_body, region, account_id, partition, parameters)

    def parse(self, **kwargs):
        with patch.object(cfn_policy_validator, '_inner_parse') as self.mock:
            parse({}, account_config.region, account_config.account_id, account_config.partition, **kwargs)

    def parse_with_expected_error(self, error_message, **kwargs):
        with self.assertRaises(ArgumentTypeError) as error:
            parse({}, account_config.region, **kwargs)

        self.assertIn(error_message, str(error.exception))

    def test_with_no_parameters(self):
        self.parse()
        self.assert_called_with(parameters={})

    def test_with_parameters(self):
        self.parse(template_parameters={
            'Key1': 'Value1',
            'Key2': 'Value2'
        })
        self.assert_called_with(parameters={'Key1': 'Value1', 'Key2': 'Value2'})
