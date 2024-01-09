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
	sample_policy_a, assume_role_policy_doc, IdentityParserTest


class WhenParsingARolePolicyAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'Resources.RolePolicy'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_name(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'RoleName': 'MyRole'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyName', 'Resources.RolePolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_name_type(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyName': ['Invalid'],
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'RoleName': 'MyRole'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.RolePolicy.Properties.PolicyName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyName': 'MyPolicy',
					'RoleName': 'MyRole'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'Resources.RolePolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': 'Invalid',
					'RoleName': 'MyRole'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.RolePolicy.Properties.PolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_role_name(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('RoleName', 'Resources.RolePolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_role_name_type(self):
		template = load_resources({
			'RolePolicy': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'RoleName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.RolePolicy.Properties.RoleName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'RoleName': 'MyRole'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::RolePolicy',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'RoleName': 'MyRole'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingARolePolicyWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a role policy
	@mock_identity_parser_setup()
	def test_returns_a_role_with_references_resolved(self):
		role_policy = {
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
				'Path': {},
				'Name': {},
				'Resource': {}
			},
			'Resources': {
				'RolePolicy': {
					'Type': 'AWS::IAM::RolePolicy',
					'Properties': {
						'PolicyDocument': role_policy,
						'PolicyName': {'Ref': 'Name'},
						'RoleName': {'Ref': 'Role'}
					}
				},
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		}, {
			'Path': '/custom/policy/path',
			'Name': 'PolicyName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		expected_role_policy = role_policy.copy()
		expected_role_policy['Statement'][0]['Resource'] = 'my_resource/*'

		role = self.roles[0]
		self.assertEqual(1, len(role.Policies))
		self.assertTrue(has_policy(role, 'PolicyName', expected_role_policy))


class WhenParsingARolePolicyAttachedToRole(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_role_with_attached_policy(self):
		template = load({
			'Resources': {
				'RolePolicy': {
					'Type': 'AWS::IAM::RolePolicy',
					'Properties': {
						'PolicyName': 'RolePolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'RoleName': {'Ref': 'RoleA'}
					}
				},
				'RoleA': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role_a = self.roles[0]
		self.assertEqual(1, len(role_a.Policies))
		self.assertTrue(has_policy(role_a, "RolePolicy", sample_policy_a))


class WhenParsingAPolicyThatIsAttachedToAnExternalRole(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_an_orphaned_policy(self):
		template = load({
			'Parameters': {
				'RoleA': {}
			},
			'Resources': {
				'Policy': {
					'Type': 'AWS::IAM::RolePolicy',
					'Properties': {
						'PolicyName': 'MyPolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'RoleName': {'Ref': 'RoleA'}
					}
				}
			}
		}, {
			'RoleA': 'MyRoleA'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=1)

		policy = self.orphaned_policies[0]
		self.assertEqual("MyPolicy", policy.Name)
		self.assertEqual("/", policy.Path)
		self.assertEqual(sample_policy_a, policy.Policy)


class WhenParsingMultipleRolePoliciesWithTheSameName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_all_inline_policies(self):
		role_policy_a = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:RunInstances',
					'Resource': "*"
				}
			]
		}

		role_policy_b = {
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
				'RolePolicyA': {
					'Type': 'AWS::IAM::RolePolicy',
					'Properties': {
						'PolicyDocument': role_policy_a,
						'PolicyName': 'Policy',
						'RoleName': 'MyExternalRole'
					}
				},
				'RolePolicyB': {
					'Type': 'AWS::IAM::RolePolicy',
					'Properties': {
						'PolicyDocument': role_policy_b,
						'PolicyName': 'Policy',
						'RoleName': 'MyExternalRole'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=2)

		policy = self.orphaned_policies[0]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(role_policy_a, policy.Policy)

		policy = self.orphaned_policies[1]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(role_policy_b, policy.Policy)
