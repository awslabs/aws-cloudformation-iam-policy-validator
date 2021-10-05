"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import unittest
from argparse import Namespace

from unittest.mock import patch, ANY, DEFAULT

import boto3

from cfn_policy_validator import main, client
from cfn_policy_validator.tests import ParsingTest, account_config, ValidationTest, mock_validation_setup, end_to_end, \
    BotoResponse, mock_test_setup
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.validation.reporter import ResourceOrCodeFindingToIgnore, ResourceAndCodeFindingToIgnore, \
    AllowedExternalPrincipal, AllowedExternalArn, default_finding_types_that_are_blocking
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests.utils import captured_output, ignore_warnings
from cfn_policy_validator.version import __version__


this_files_directory = os.path.dirname(os.path.realpath(__file__))


def build_default_arguments(template_path=""):
    default_args = Namespace(
        template_path=template_path,
        region=account_config.region,
        parameters={},
        ignore_finding=None,
        treat_as_blocking=default_finding_types_that_are_blocking,
        allowed_external_principals=None,
        profile=None,
        func=ANY
    )
    return default_args


def build_default_parse_args(template_path=''):
    default_args = Namespace(
        template_path=template_path,
        region=account_config.region,
        parameters={},
        profile=None,
        func=ANY
    )
    return default_args


class WhenParsingATemplateAsCLI(ParsingTest):
    def setUp(self):
        # ignore ResourceWarnings to avoid output being polluted by them
        # unittest resets this after every test, so it needs to go in setUp
        ignore_warnings()

    @end_to_end
    def test_prints_parser_output(self):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
        with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
            main.main([
                'parse',
                '--template-path', json_file_path,
                '--region', account_config.region,
                '--parameters', 'CodestarConnectionArn=fakeArn', 'EnvironmentName=prod'
            ])

        self.assertEqual(0, context_manager.exception.code, err.getvalue())

        try:
            self.output = json.loads(out.getvalue())
        except:
            self.assertTrue(False, err.getvalue())

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


class WhenValidatingATemplateAsCLI(ValidationTest):
    def setUp(self):
        ignore_warnings()

    @end_to_end
    def test_prints_report(self):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
        with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
            main.main([
                'validate',
                '--template-path', json_file_path,
                '--region', account_config.region,
                '--parameters', 'CodestarConnectionArn=fakeArn', 'EnvironmentName=prod',
                '--treat-finding-type-as-blocking', 'ERROR,SECURITY_WARNING',
                '--ignore-finding', 'MyIAMUser.PASS_ROLE_WITH_STAR_IN_RESOURCE',
                '--allow-external-principal', '123456789123'
            ])

        err_value = err.getvalue()
        if err_value != '':
            print(err_value)

        self.assertEqual(2, context_manager.exception.code)

        try:
            self.output = json.loads(out.getvalue())
        except:
            self.assertTrue(False, err.getvalue())

        self.assertEqual(2, len(self.output['NonBlockingFindings']))
        self.assert_warning('WARNING', 'MISSING_VERSION', 'prod-app-artifacts', 'BucketPolicy')
        self.assert_warning('WARNING', 'MISSING_VERSION', 'MyQueue', 'QueuePolicy')

        self.assertEqual(5, len(self.output['BlockingFindings']))
        self.assert_error('ERROR', 'MISSING_ARN_FIELD', 'CodePipelineServiceRole', 'root')
        self.assert_error('ERROR', 'MISSING_PRINCIPAL', 'MyQueue', 'QueuePolicy')
        self.assert_error('SECURITY_WARNING', 'PASS_ROLE_WITH_STAR_IN_RESOURCE', 'CodePipelineServiceRole', 'root')
        self.assert_error('SECURITY_WARNING', 'PASS_ROLE_WITH_STAR_IN_RESOURCE', 'MyIAMGroup', 'root')
        self.assert_error('SECURITY_WARNING', 'EXTERNAL_PRINCIPAL', 'prod-app-artifacts', 'BucketPolicy')


class WhenParsingArgumentsForVersion(unittest.TestCase):
    def setUp(self):
        self.args = [
            '--version'
        ]

    def test_returns_version(self):
        with self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(self.args)

        self.assertEqual(0, context_manager.exception.code)
        self.assertIn(__version__, out.getvalue())


class WhenParsingArgumentsForValidate(unittest.TestCase):
    def setUp(self):
        self.args = [
            'validate',
            '--template-path', 'abcdef',
            '--region', account_config.region
        ]
        ignore_warnings()

    def assert_called_with(self, parameters=ANY, ignore_finding=ANY, treat_as_blocking=ANY, allowed_external_principals=ANY):
        arguments = build_default_arguments(template_path='abcdef')
        arguments.parameters = parameters
        arguments.ignore_finding = ignore_finding
        arguments.treat_as_blocking = treat_as_blocking
        arguments.allowed_external_principals = allowed_external_principals
        arguments.template_configuration_file = None
        arguments.enable_logging = False
        setattr(arguments, '{parse,validate}', ANY)

        self.mock.assert_called_with(arguments)

    def validate(self):
        with patch.object(main, 'validate_from_cli') as self.mock:
            main.main(args=self.args)

    def validate_with_expected_error(self, error_message):
        with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
            main.main(self.args)

        self.assertEqual(2, context_manager.exception.code)
        self.assertIn(error_message, err.getvalue())

    @mock_validation_setup()
    def test_path_is_required(self):
        self.args = [
            'validate', '--region', account_config.region
        ]

        self.validate_with_expected_error("the following arguments are required: --template-path")

    @mock_validation_setup()
    def test_region_is_required(self):
        self.args = [
            'validate', '--template-path', 'abcdef'
        ]
        self.validate_with_expected_error("the following arguments are required: --region")

    @mock_validation_setup()
    def test_with_no_parameters(self):
        self.validate()
        self.assert_called_with(parameters={})

    @mock_validation_setup()
    def test_parameters_are_parsed_to_dictionary(self):
        self.args.extend(['--parameters', 'Key1=Value1', 'Key2=Value2'])
        self.validate()
        self.assert_called_with(parameters={'Key1': 'Value1', 'Key2': 'Value2'})

    @mock_validation_setup()
    def test_parameters_with_invalid_format(self):
        # this is just to ensure the parsing doesn't blow up if someone specifies parameters like this
        self.args.extend(['--parameters', 'Key1=Value1,Key2=Value2'])
        self.validate()
        self.assert_called_with(parameters={'Key1': 'Value1,Key2=Value2'})

    @mock_validation_setup()
    def test_ignore_finding_default_is_none(self):
        self.validate()
        self.assert_called_with(ignore_finding=None)

    @mock_validation_setup()
    def test_treat_as_blocking_default(self):
        self.validate()
        self.assert_called_with(treat_as_blocking=['ERROR', 'SECURITY_WARNING'])

    def test_treat_as_blocking_is_upper_cased(self):
        self.args.extend(['--treat-finding-type-as-blocking', 'warning,error'])
        self.validate()
        self.assert_called_with(treat_as_blocking=['WARNING', 'ERROR'])

    @mock_validation_setup()
    def test_treat_as_blocking_removes_whitespace(self):
        self.args.extend(['--treat-finding-type-as-blocking', 'warning  , error '])
        self.validate()
        self.assert_called_with(treat_as_blocking=['WARNING', 'ERROR'])

    @mock_validation_setup()
    def test_treat_as_blocking_parsed_to_a_list(self):
        self.args.extend(['--treat-finding-type-as-blocking', 'error'])
        self.validate()
        self.assert_called_with(treat_as_blocking=['ERROR'])

    @mock_validation_setup()
    def test_ignore_finding_with_resource_parsed_to_class(self):
        self.args.extend(['--ignore-finding', 'MyResource'])
        self.validate()

        expected = ResourceOrCodeFindingToIgnore('MyResource')
        self.assert_called_with(ignore_finding=[expected])

    @mock_validation_setup()
    def test_ignore_finding_with_code_parsed_to_class(self):
        self.args.extend(['--ignore-finding', 'PASS_ROLE_WITH_STAR_IN_RESOURCE'])
        self.validate()

        expected = ResourceOrCodeFindingToIgnore('PASS_ROLE_WITH_STAR_IN_RESOURCE')
        self.assert_called_with(ignore_finding=[expected])

    @mock_validation_setup()
    def test_ignore_finding_with_code_and_resource_parsed_to_class(self):
        self.args.extend(['--ignore-finding', 'MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE'])
        self.validate()

        expected = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        self.assert_called_with(ignore_finding=[expected])

    @mock_validation_setup()
    def test_ignore_finding_with_multiple_findings_to_ignore(self):
        self.args.extend(['--ignore-finding', 'MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE,MyResource2'])
        self.validate()

        expected1 = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        expected2 = ResourceOrCodeFindingToIgnore('MyResource2')
        self.assert_called_with(ignore_finding=[expected1, expected2])

    @mock_validation_setup()
    def test_ignore_finding_with_extra_whitespace(self):
        self.args.extend(['--ignore-finding', 'MyResource.PASS_ROLE_WITH_STAR_IN_RESOURCE,     MyResource2'])
        self.validate()

        expected1 = ResourceAndCodeFindingToIgnore('MyResource', 'PASS_ROLE_WITH_STAR_IN_RESOURCE')
        expected2 = ResourceOrCodeFindingToIgnore('MyResource2')
        self.assert_called_with(ignore_finding=[expected1, expected2])

    @mock_validation_setup()
    def test_allow_external_principals_with_account_id_parsed_to_class(self):
        self.args.extend(['--allow-external-principals', '123456789123'])
        self.validate()

        expected = AllowedExternalPrincipal('123456789123')
        self.assert_called_with(allowed_external_principals=[expected])

    @mock_validation_setup()
    def test_allow_external_principals_with_arn_parsed_to_class(self):
        self.args.extend(['--allow-external-principals', 'arn:aws:iam::123456789123:role/MyOtherRole'])
        self.validate()

        expected = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected])

    @mock_validation_setup()
    def test_allow_external_principals_with_multiple_principals(self):
        self.args.extend(['--allow-external-principals', '123456789123,arn:aws:iam::123456789123:role/MyOtherRole'])
        self.validate()

        expected1 = AllowedExternalPrincipal('123456789123')
        expected2 = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected1, expected2])

    @mock_validation_setup()
    def test_allow_external_principals_with_extra_whitespace(self):
        self.args.extend(['--allow-external-principals', '123456789123,     arn:aws:iam::123456789123:role/MyOtherRole'])
        self.validate()

        expected1 = AllowedExternalPrincipal('123456789123')
        expected2 = AllowedExternalArn('arn:aws:iam::123456789123:role/MyOtherRole')
        self.assert_called_with(allowed_external_principals=[expected1, expected2])

    @mock_validation_setup()
    def test_allow_external_principals_with_value_that_contains_arn(self):
        # test that even values that contain the word "arn" aren't parsed as ARNs
        self.args.extend(['--allow-external-principals', 'warning'])
        self.validate()

        expected = AllowedExternalPrincipal('warning')
        self.assert_called_with(allowed_external_principals=[expected])


class WhenParsingArgumentsForParse(unittest.TestCase):
    def setUp(self):
        self.args = [
            'parse',
            '--template-path', 'abcdef',
            '--region', account_config.region
        ]
        ignore_warnings()

    def assert_called_with(self, parameters=ANY):
        arguments = build_default_parse_args(template_path='abcdef')
        arguments.parameters = parameters
        arguments.template_configuration_file = None
        arguments.enable_logging = False
        setattr(arguments, '{parse,validate}', ANY)

        self.mock.assert_called_with(arguments)

    def parse(self):
        with patch.object(main, 'parse_from_cli') as self.mock:
            main.main(args=self.args)

    def parse_with_expected_error(self, error_message):
        with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
            main.main(self.args)

        self.assertEqual(2, context_manager.exception.code)
        self.assertIn(error_message, err.getvalue())

    @mock_validation_setup()
    def test_with_no_parameters(self):
        self.parse()
        self.assert_called_with(parameters={})

    @mock_validation_setup()
    def test_parameters_are_parsed_to_dictionary(self):
        self.args.extend(['--parameters', 'Key1=Value1', 'Key2=Value2'])
        self.parse()
        self.assert_called_with(parameters={'Key1': 'Value1', 'Key2': 'Value2'})

    @mock_validation_setup()
    def test_parameters_with_invalid_format(self):
        # this is just to ensure the parsing doesn't blow up if someone specifies parameters like this
        self.args.extend(['--parameters', 'Key1=Value1,Key2=Value2'])
        self.parse()
        self.assert_called_with(parameters={'Key1': 'Value1,Key2=Value2'})

    @mock_validation_setup()
    def test_path_is_required(self):
        self.args = [
            'parse', '--region', account_config.region
        ]

        self.parse_with_expected_error("the following arguments are required: --template-path")

    @mock_validation_setup()
    def test_region_is_required(self):
        self.args = [
            'parse', '--template-path', 'abcdef'
        ]
        self.parse_with_expected_error("the following arguments are required: --region")


class WhenAnErrorOccursWhileValidatingTemplate(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_an_application_error(self):
        with patch.object(main, 'validate_from_cli', side_effect=ApplicationError('Something went wrong')), \
                self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(args=[
                'validate',
                '--template-path', 'abcdef',
                '--region', 'us-east-1'
            ])

        self.assertEqual(1, context_manager.exception.code)
        self.assertEqual(err.getvalue(), "ERROR: Something went wrong\n")

    @mock_validation_setup()
    def test_a_generic_error(self):
        with patch.object(main, 'validate_from_cli', side_effect=Exception('Something went wrong')), \
                self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(args=[
                'validate',
                '--template-path', 'abcdef',
                '--region', 'us-east-1'
            ])

        self.assertEqual(1, context_manager.exception.code)
        self.assertIn("ERROR: Unexpected error occurred. Something went wrong\n", err.getvalue())


class WhenParsingAnInvalidJsonFile(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_exits_and_prints_error_message(self):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/invalid_file.json')

        with self.assertRaises(ApplicationError) as err:
            main.validate_from_cli(build_default_arguments(json_file_path))

        self.assertEqual(str(err.exception),
                         "Unable to parse CloudFormation template.  Invalid YAML or JSON detected.")


class WhenParsingAnInvalidYamlFile(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_exits_and_prints_error_message(self):
        yaml_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/invalid_file.yaml')

        with self.assertRaises(ApplicationError) as err:
            main.validate_from_cli(build_default_arguments(yaml_file_path))

        self.assertEqual(str(err.exception),
                         "Unable to parse CloudFormation template.  Invalid YAML or JSON detected.")


class WhenParsingTemplateThatThrowsAnError(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_exits_and_prints_error_message(self):
        with patch.object(main, '_parse_template_file', side_effect=ApplicationError('Something went wrong')), \
                self.assertRaises(ApplicationError) as err:
            main.validate_from_cli(build_default_arguments())

        self.assertEqual("Something went wrong", str(err.exception))


class WhenParsingTemplateThatDoesNotExist(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_exits_and_prints_error_message(self):
        yaml_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/does_not_exist.yaml')

        with self.assertRaises(ApplicationError) as err:
            main.validate_from_cli(build_default_arguments(yaml_file_path))

        self.assertEqual(str(err.exception),
                         f'CloudFormation template not found: {yaml_file_path}')


class WhenParsingTemplateConfigurationFile(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    def build_args(self, template_configuration_file):
        json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
        template_configuration_file = os.path.join(this_files_directory, '..', '..', template_configuration_file)
        return [
            'parse',
            '--template-path', json_file_path,
            '--region', account_config.region,
            '--template-configuration-file', template_configuration_file
        ]

    @mock_validation_setup()
    def test_when_used_without_explicit_parameters(self):
        args = self.build_args('test_files/template_configuration_file.json')

        with patch.object(main, 'parse_from_cli') as mock:
            main.main(args)

        expected_args = Namespace(
            template_path=ANY,
            region=account_config.region,
            template_configuration_file=ANY,
            parameters={
                'CodestarConnectionArn': 'fakearn',
                'EnvironmentName': 'test'
            },
            profile=ANY,
            func=ANY,
            enable_logging=ANY
        )
        setattr(expected_args, '{parse,validate}', ANY)

        mock.assert_called_once()
        mock.assert_called_with(expected_args)

    @mock_validation_setup()
    def test_is_overwritten_by_parameters(self):
        args = self.build_args('test_files/template_configuration_file.json')
        args.extend(['--parameters', 'EnvironmentName=prod', 'OtherParam=Other'])

        with patch.object(main, 'parse_from_cli') as mock:
            main.main(args)

        expected_args = Namespace(
            template_path=ANY,
            region=account_config.region,
            template_configuration_file=ANY,
            parameters={
                'CodestarConnectionArn': 'fakearn',
                'EnvironmentName': 'prod',
                'OtherParam': 'Other'
            },
            profile=ANY,
            func=ANY,
            enable_logging=ANY
        )
        setattr(expected_args, '{parse,validate}', ANY)

        mock.assert_called_once()
        mock.assert_called_with(expected_args)

    @mock_validation_setup()
    def test_with_invalid_parameters_in_file(self):
        args = self.build_args('test_files/template_configuration_invalid_parameters.json')

        with self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(args)

        self.assertEqual(1, context_manager.exception.code)
        self.assertIn('ERROR: The value for "Parameters" in the template configuration value must be a JSON object.', err.getvalue())

    @mock_validation_setup()
    def test_with_file_that_doesnt_exist(self):
        args = self.build_args('test_files/does_not_exist.json')

        with self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(args)

        self.assertEqual(1, context_manager.exception.code)
        self.assertIn('ERROR: Template configuration file not found: ', err.getvalue())

    @mock_validation_setup()
    def test_with_invalid_file_json(self):
        args = self.build_args('test_files/template_configuration_invalid_json.json')

        with self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main(args)

        self.assertEqual(1, context_manager.exception.code)
        self.assertIn('ERROR: Template configuration file contains invalid json', err.getvalue())


class WhenRunningWithNoSubparser(unittest.TestCase):
    def setUp(self):
        ignore_warnings()

    @mock_validation_setup()
    def test_returns_error_message(self):
        with self.assertRaises(SystemExit) as context_manager, \
                captured_output() as (out, err):
            main.main([])

        self.assertEqual(2, context_manager.exception.code)
        self.assertIn('error: the following arguments are required: {parse,validate}', err.getvalue())


class WhenSettingProfileAndRegion(unittest.TestCase):
    def setUp(self):
        client.set_profile(None)

    def tearDown(self):
        client.set_profile(None)

    @end_to_end
    def test_calls_to_boto3_session_must_include_profile_and_region(self):
        expected_profile_name = "default"
        expected_region_name = account_config.region
        self.profile_is_set = False
        self.profile_is_mocked = False

        def validate_profile_is_set(profile_name, region_name):
            if self.profile_is_mocked:
                self.profile_is_mocked = False
                return DEFAULT

            self.assertEqual(expected_profile_name, profile_name)
            self.assertEqual(expected_region_name, region_name)
            self.profile_is_set = True

            # for the sake of testing, we just want to validate the profile is set, we trust the behavior of boto to
            # use the profile.  This also avoids having to configure profiles to run the tests
            self.profile_is_mocked = True
            return boto3.Session(profile_name=None, region_name=region_name)

        with patch('cfn_policy_validator.client.boto3.Session', wraps=client.boto3.Session, side_effect=validate_profile_is_set):
            json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
            with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
                main.main([
                    'validate',
                    '--template-path', json_file_path,
                    '--region', account_config.region,
                    '--parameters', 'CodestarConnectionArn=fakeArn', 'EnvironmentName=prod',
                    '--profile', expected_profile_name
                ])

        self.assertEqual(2, context_manager.exception.code, print("output: " + out.getvalue() + "\n err: " + err.getvalue()))
        self.assertTrue(self.profile_is_set, 'Expected profile to be set.')

    @end_to_end
    def test_calls_to_boto3_session_must_only_include_region_with_no_profile_set(self):
        expected_region_name = account_config.region

        def validate_profile_is_set(profile_name, region_name):
            self.assertIsNone(profile_name)
            self.assertEqual(expected_region_name, region_name)
            return DEFAULT

        with patch('cfn_policy_validator.client.boto3.Session', wraps=client.boto3.Session, side_effect=validate_profile_is_set):
            json_file_path = os.path.join(this_files_directory, '..', '..', 'test_files/test_file_2.json')
            with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
                main.main([
                    'validate',
                    '--template-path', json_file_path,
                    '--region', account_config.region,
                    '--parameters', 'CodestarConnectionArn=fakeArn', 'EnvironmentName=prod'
                ])

        self.assertEqual(2, context_manager.exception.code, print("output: " + out.getvalue() + "\n err: " + err.getvalue()))
