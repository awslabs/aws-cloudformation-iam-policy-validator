"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.tests import offline_only
from cfn_policy_validator.tests.boto_mocks import BotoClientError
from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity import IdentityParser

from cfn_policy_validator.tests.parsers_tests.test_identity import has_policy, sample_policy_a, sample_policy_b, \
	IdentityParserTest, aws_lambda_basic_execution_response, aws_lambda_execute_response, \
	aws_lambda_basic_execution_version_response, aws_lambda_execute_version_response


class WhenParsingAPermissionSetAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Name', 'Resources.ResourceA.Properties'),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': {'Value': 'Invalid'}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Name', 'string', "{'Value': 'Invalid'}"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_valid_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'permissionset.a.b.c'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'No validation error raised')


	@mock_identity_parser_setup()
	def test_with_invalid_inline_policy_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'MyPermissionSet',
					'InlinePolicy': 'PolicyA'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.InlinePolicy', 'object', "'PolicyA'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policies_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'MyPermissionSet',
					'ManagedPolicies': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ManagedPolicies', 'array', "'Invalid'"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policies_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'MyPermissionSet',
					'ManagedPolicies': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ManagedPolicies.0', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'MyPermissionSet',
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SSO::PermissionSet',
				'Properties': {
					'Name': 'MyPermissionSet',
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAPermissionSetWithAName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_permission_set(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual("MyPermissionSet", permission_set.Name)
		self.assertEqual(0, len(permission_set.Policies))


class WhenParsingAnInlinePolicyAttachedToAPermissionSet(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_permission_set_and_policy(self):
		template = load({
			'Resources': {
				'PermissionSet': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet',
						'InlinePolicy': copy.deepcopy(sample_policy_a)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual("MyPermissionSet", permission_set.Name)
		self.assertEqual(1, len(permission_set.Policies))

		self.assertTrue(has_policy(permission_set, 'InlinePolicy', sample_policy_a))


class WhenParsingAPermissionSetWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a permission set
	@mock_identity_parser_setup()
	def test_returns_a_permission_set_with_references_resolved(self):
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
				'Name': {},
				'ServiceName': {},
				'Resource': {}
			},
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				},
				'ResourceA': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': {'Ref': 'Name'},
						'InlinePolicy': inline_policy,
						'ManagedPolicies': [
							{'Ref': 'ManagedPolicy'}
						]
					}
				}
			}
		}, {
			'Name': 'CustomName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual("CustomName", permission_set.Name)

		expected_inline_policy = inline_policy.copy()
		expected_inline_policy['Statement'][0]['Resources'] = 'my_resource/*'

		self.assertEqual(2, len(permission_set.Policies))
		self.assertTrue(has_policy(permission_set, 'InlinePolicy', expected_inline_policy))
		self.assertTrue(has_policy(permission_set, "ManagedPolicy", sample_policy_a))


class WhenParsingManagedPoliciesAttachedToAPermissionSet(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_permission_sets_with_attached_policies(self):
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
				'PermissionSet': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet',
						'ManagedPolicies': [
							{'Ref': 'ManagedPolicyA'},
							{'Ref': 'ManagedPolicyB'}
						]
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual(2, len(permission_set.Policies))
		self.assertTrue(has_policy(permission_set, "ManagedPolicyA", sample_policy_a))
		self.assertTrue(has_policy(permission_set, "ManagedPolicyB", sample_policy_b))


# note that the DependsOn is required here, otherwise the managed policy would not exist when the permission set attempts to find it
class WhenParsingManagedPoliciesAttachedToAPermissionSetAndArnIsNotRef(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_permission_sets_with_attached_policies(self):
		template = load({
			'Resources': {
				'PermissionSet': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet',
						'ManagedPolicies': [
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
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual(1, len(permission_set.Policies))
		self.assertTrue(has_policy(permission_set, "MyManagedPolicy", sample_policy_a))


class WhenParsingManagedPolicyAttachedToAPermissionSetAndThePolicyIsAWSManaged(IdentityParserTest):
	@mock_identity_parser_setup(
		iam=[
			aws_lambda_basic_execution_response(),
			aws_lambda_basic_execution_version_response(),
			aws_lambda_execute_response(),
			aws_lambda_execute_version_response()
		]
	)
	@offline_only
	def test_returns_permission_set_with_attached_policies(self):
		template = load({
			'Resources': {
				'PermissionSet': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet',
						'ManagedPolicies': [
							'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
							'arn:aws:iam::aws:policy/AWSLambdaExecute'
						]
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_permission_sets=1)

		permission_set = self.permission_sets[0]
		self.assertEqual(2, len(permission_set.Policies))
		self.assertTrue(has_policy(permission_set, "AWSLambdaBasicExecutionRole", sample_policy_a, '/service-role/'))
		self.assertTrue(has_policy(permission_set, "AWSLambdaExecute", sample_policy_b, '/'))


class WhenParsingManagedPolicyAttachedToAPermissionSetAndThePolicyDoesNotExistInTemplateOrAWS(unittest.TestCase):
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
				'PermissionSet': {
					'Type': 'AWS::SSO::PermissionSet',
					'Properties': {
						'Name': 'MyPermissionSet',
						'ManagedPolicies': [
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
