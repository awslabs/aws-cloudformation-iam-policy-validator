"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from unittest.mock import patch, MagicMock

from cfn_policy_validator.tests import offline_only
from cfn_policy_validator.tests.boto_mocks import BotoClientError
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.parsers import identity

from cfn_policy_validator.tests.parsers_tests.test_identity import has_policy, \
	sample_policy_a, sample_policy_b, IdentityParserTest, aws_lambda_basic_execution_response, \
	aws_lambda_basic_execution_version_response, aws_lambda_execute_response, aws_lambda_execute_version_response


class WhenParsingAnIAMUserAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_invalid_path_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Path': {'abc': 'def'}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Path', 'string', "{'abc': 'def'}"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_user_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'UserName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.UserName', 'string', "['Invalid']"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policies_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': 'PolicyA'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Policies', 'array', "'PolicyA'"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policies_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': ['PolicyA']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Policies.0', 'object', "'PolicyA'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': [
						{
							'PolicyDocument': copy.deepcopy(sample_policy_b)
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyName', 'Resources.ResourceA.Properties.Policies.0'),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': [
						{
							'PolicyName': ['Invalid'],
							'PolicyDocument': copy.deepcopy(sample_policy_a)
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(
			expected_type_error('Resources.ResourceA.Properties.Policies.0.PolicyName', 'string', "['Invalid']"),
			str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': [
						{
							'PolicyName': 'root'
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'Resources.ResourceA.Properties.Policies.0'),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'Policies': [
						{
							'PolicyName': 'PolicyA',
							'PolicyDocument': 'Invalid'
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(
			expected_type_error('Resources.ResourceA.Properties.Policies.0.PolicyDocument', 'object', "'Invalid'"),
			str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_arns_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'ManagedPolicyArns': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ManagedPolicyArns', 'array', "'Invalid'"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_arns_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'ManagedPolicyArns': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ManagedPolicyArns.0', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'LoginProfile': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::User',
				'Properties': {
					'LoginProfile': {'Ref': 'SomeProperty'}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnIAMUserWithAName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_user(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'Path': '/custom/user/path',
						'UserName': 'MyUserName'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual("MyUserName", user.UserName)
		self.assertEqual("/custom/user/path", user.UserPath)
		self.assertEqual(0, len(user.Policies))


class WhenParsingAnIAMUserWithNoName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_user(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'Path': '/custom/user/path'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual("ResourceA", user.UserName)
		self.assertEqual("/custom/user/path", user.UserPath)
		self.assertEqual(0, len(user.Policies))


class WhenParsingAnIAMPolicyAttachedToAUser(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_user_and_policy(self):
		template = load({
			'Resources': {
				'User': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'Policies': [
							{
								'PolicyName': 'PolicyA',
								'PolicyDocument': copy.deepcopy(sample_policy_a)
							},
							{
								'PolicyName': 'PolicyB',
								'PolicyDocument': copy.deepcopy(sample_policy_b)
							}
						]
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual("User", user.UserName)
		self.assertEqual("/", user.UserPath)
		self.assertEqual(2, len(user.Policies))

		self.assertTrue(has_policy(user, 'PolicyA', sample_policy_a))
		self.assertTrue(has_policy(user, 'PolicyB', sample_policy_b))


class WhenParsingAnIAMUserWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a user
	@mock_identity_parser_setup()
	def test_returns_a_user_with_references_resolved(self):
		inline_policy = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:RunInstance',
					'Resources': {'Ref': 'Resource'}
				}
			]
		}

		template = load({
			'Parameters': {
				'UserPath': {},
				'UserName': {},
				'Resource': {},
				'ManagedPolicyArn': {}
			},
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				},
				'ResourceA': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'Path': {'Ref': 'UserPath'},
						'UserName': {'Ref': 'UserName'},
						'Policies': [{
							'PolicyName': 'Policy1',
							'PolicyDocument': inline_policy
						}],
						'ManagedPolicyArns': [
							{'Ref': 'ManagedPolicy'}
						]
					}
				}
			}
		},
			{
				'UserPath': '/custom/user/path',
				'UserName': 'CustomUserName',
				'Resource': 'my_resource/*'
			}
		)

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual("CustomUserName", user.UserName)
		self.assertEqual("/custom/user/path", user.UserPath)

		expected_inline_policy = inline_policy.copy()
		expected_inline_policy['Statement'][0]['Resources'] = 'my_resource/*'

		self.assertEqual(2, len(user.Policies))
		self.assertTrue(has_policy(user, 'Policy1', expected_inline_policy))
		self.assertTrue(has_policy(user, "ManagedPolicy", sample_policy_a))


class WhenParsingManagedPoliciesAttachedToAUserFromTheUser(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_user_with_attached_policies(self):
		template = load({
			'Resources': {
				'ManagedPolicyA': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				},
				'ManagedPolicyB': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_b)
					}
				},
				'User': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'ManagedPolicyArns': [
							{'Ref': 'ManagedPolicyA'},
							{'Ref': 'ManagedPolicyB'}
						]
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual(2, len(user.Policies))
		self.assertTrue(has_policy(user, "ManagedPolicyA", sample_policy_a))
		self.assertTrue(has_policy(user, "ManagedPolicyB", sample_policy_b))


# note that the DependsOn is required here, otherwise the managed policy would not exist when the user attempts to find it
class WhenParsingManagedPoliciesAttachedToAUserFromTheUserAndArnIsNotRef(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_users_with_attached_policies(self):
		template = load({
			'Resources': {
				'User': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'ManagedPolicyArns': [
							f"arn:aws:iam::{account_config.account_id}:policy/MyManagedPolicy"
						]
					},
					'DependsOn': 'ManagedPolicyA'
				},
				'ManagedPolicyA': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						"ManagedPolicyName": "MyManagedPolicy",
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual(1, len(user.Policies))
		self.assertTrue(has_policy(user, "MyManagedPolicy", sample_policy_a))


class WhenParsingManagedPolicyAttachedToAUserAndThePolicyIsAWSManaged(IdentityParserTest):
	@mock_identity_parser_setup(
		iam=[
			aws_lambda_basic_execution_response(),
			aws_lambda_basic_execution_version_response(),
			aws_lambda_execute_response(),
			aws_lambda_execute_version_response()
		]
	)
	@offline_only
	def test_returns_user_with_attached_policies(self):
		template = load({
			'Resources': {
				'User': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'ManagedPolicyArns': [
							'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
							'arn:aws:iam::aws:policy/AWSLambdaExecute'
						]
					}
				}
			}
		})

		self.parse(template, account_config)

		self.assertResults(number_of_users=1)

		user = self.users[0]
		self.assertEqual(2, len(user.Policies))
		self.assertTrue(has_policy(user, "AWSLambdaBasicExecutionRole", sample_policy_a, '/service-role/'))
		self.assertTrue(has_policy(user, "AWSLambdaExecute", sample_policy_b, '/'))


class WhenParsingManagedPolicyAttachedToAUserAndThePolicyDoesNotExistInTemplateOrAWS(unittest.TestCase):
	@mock_identity_parser_setup(
		iam=[
			BotoClientError(
				method='get_policy',
				service_error_code='NoSuchEntity',
				expected_params={
					'PolicyArn': 'arn:aws:iam::aws:policy/DoesNotExist'
				}
			)
		]
	)
	def test_throws_exception(self):
		template = load({
			'Resources': {
				'User': {
					'Type': 'AWS::IAM::User',
					'Properties': {
						'ManagedPolicyArns': [
							'arn:aws:iam::aws:policy/DoesNotExist'
						]
					}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual('Could not find managed policy with arn:aws:iam::aws:policy/DoesNotExist in template '
							'or in environment.', str(cm.exception))
