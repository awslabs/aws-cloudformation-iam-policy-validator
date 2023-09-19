"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.tests.parsers_tests import mock_identity_parser_setup
from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity import IdentityParser

from cfn_policy_validator.tests.parsers_tests.test_identity import has_policy, \
	sample_policy_a, IdentityParserTest


class WhenParsingAUserPolicyAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'UserPolicy'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_name(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'UserName': 'MyUser'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyName', 'UserPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_name_type(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyName': ['Invalid'],
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'UserName': 'MyUser'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('UserPolicy.Properties.PolicyName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyName': 'MyPolicy',
					'UserName': 'MyUser'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'UserPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': 'Invalid',
					'UserName': 'MyUser'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('UserPolicy.Properties.PolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_user_name(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('UserName', 'UserPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_user_name_type(self):
		template = load_resources({
			'UserPolicy': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'UserName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('UserPolicy.Properties.UserName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'UserName': 'MyUser'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::UserPolicy',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'UserName': 'MyUser'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAUserPolicyWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a user policy
	@mock_identity_parser_setup()
	def test_returns_a_user_with_references_resolved(self):
		user_policy = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:RunInstance',
					'Resource': {'Ref': 'Resource'}
				}
			]
		}

		template = load({
			'Parameters': {
				'Name': {},
				'Resource': {}
			},
			'Resources': {
				'UserPolicy': {
					'Type': 'AWS::IAM::UserPolicy',
					'Properties': {
						'PolicyDocument': user_policy,
						'PolicyName': {'Ref': 'Name'},
						'UserName': {'Ref': 'User'}
					}
				},
				'User': {
					'Type': 'AWS::IAM::User'
				}
			}
		}, {
			'Name': 'PolicyName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		expected_user_policy = user_policy.copy()
		expected_user_policy['Statement'][0]['Resource'] = 'my_resource/*'

		user = self.users[0]
		self.assertEqual(1, len(user.Policies))
		self.assertTrue(has_policy(user, 'PolicyName', expected_user_policy))


class WhenParsingAUserPolicyAttachedToUser(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_user_with_attached_policy(self):
		template = load({
			'Resources': {
				'UserPolicy': {
					'Type': 'AWS::IAM::UserPolicy',
					'Properties': {
						'PolicyName': 'UserPolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'UserName': {'Ref': 'UserA'}
					}
				},
				'UserA': {
					'Type': 'AWS::IAM::User'
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1)

		user_a = self.users[0]
		self.assertEqual(1, len(user_a.Policies))
		self.assertTrue(has_policy(user_a, "UserPolicy", sample_policy_a))


class WhenParsingAPolicyThatIsAttachedToAnExternalUser(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_an_orphaned_policy(self):
		template = load({
			'Parameters': {
				'UserA': {}
			},
			'Resources': {
				'Policy': {
					'Type': 'AWS::IAM::UserPolicy',
					'Properties': {
						'PolicyName': 'MyPolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'UserName': {'Ref': 'UserA'}
					}
				}
			}
		}, {
			'UserA': 'MyUserA'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=1)

		policy = self.orphaned_policies[0]
		self.assertEqual("MyPolicy", policy.Name)
		self.assertEqual("/", policy.Path)
		self.assertEqual(sample_policy_a, policy.Policy)


class WhenParsingMultipleUserPoliciesWithTheSameName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_all_inline_policies(self):
		user_policy_a = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:RunInstances',
					'Resource': "*"
				}
			]
		}

		user_policy_b = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:CreateNetworkInterface',
					'Resource': "*"
				}
			]
		}

		template = load({
			'Resources': {
				'UserPolicyA': {
					'Type': 'AWS::IAM::UserPolicy',
					'Properties': {
						'PolicyDocument': user_policy_a,
						'PolicyName': 'Policy',
						'UserName': 'MyExternalUser'
					}
				},
				'UserPolicyB': {
					'Type': 'AWS::IAM::UserPolicy',
					'Properties': {
						'PolicyDocument': user_policy_b,
						'PolicyName': 'Policy',
						'UserName': 'MyExternalUser'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=2)

		policy = self.orphaned_policies[0]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(user_policy_a, policy.Policy)

		policy = self.orphaned_policies[1]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(user_policy_b, policy.Policy)
