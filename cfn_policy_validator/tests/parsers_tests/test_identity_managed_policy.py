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


class WhenParsingAManagedPolicyAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'ManagedPolicyName': 'MyPolicy'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'ResourceA.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'ManagedPolicyName': ['Invalid'],
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.ManagedPolicyName', 'string', "['Invalid']"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.PolicyDocument', 'object', "'Invalid'"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_roles_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Roles': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Roles', 'array', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_role_item_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Roles': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Roles.0', 'string', "['Invalid']"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_users_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Users': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Users', 'array', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_user_item_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Users': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Users.0', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_groups_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Groups': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Groups', 'array', "'Invalid'"),
						 str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_group_item_type(self):
		template = load_resources({
			'ManagedPolicy': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'Groups': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ManagedPolicy.Properties.Groups.0', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}},
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::ManagedPolicy',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'},
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAManagedPolicyWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a managed policy
	@mock_identity_parser_setup()
	def test_returns_a_role_and_user_with_references_resolved(self):
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
				'Path': {},
				'Name': {},
				'Resource': {}
			},
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': inline_policy,
						'ManagedPolicyName': {'Ref': 'Name'},
						'Path': {'Ref': 'Path'},
						'Users': [{'Ref': 'User'}],
						'Roles': [{'Ref': 'Role'}],
						'Groups': [{'Ref': 'Group'}]
					}
				},
				'User': {
					'Type': 'AWS::IAM::User'
				},
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				},
				'Group': {
					'Type': 'AWS::IAM::Group'
				}
			}
		}, {
			'Path': '/custom/policy/path',
			'Name': 'PolicyName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=1, number_of_groups=1, number_of_roles=1)

		expected_inline_policy = inline_policy.copy()
		expected_inline_policy['Statement'][0]['Resources'] = 'my_resource/*'

		user = self.users[0]
		self.assertEqual(1, len(user.Policies))
		self.assertTrue(has_policy(user, 'PolicyName', expected_inline_policy, '/custom/policy/path'))

		group = self.groups[0]
		self.assertEqual(1, len(group.Policies))
		self.assertTrue(has_policy(group, 'PolicyName', expected_inline_policy, '/custom/policy/path'))

		role = self.roles[0]
		self.assertEqual(1, len(role.Policies))
		self.assertTrue(has_policy(role, 'PolicyName', expected_inline_policy, '/custom/policy/path'))


class WhenParsingAManagedPolicyThatIsNotAttached(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_an_orphaned_policy(self):
		template = load({
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'ManagedPolicyName': 'MyManagedPolicy',
						'Path': '/my/custom/path',
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=1)

		policy = self.orphaned_policies[0]
		self.assertEqual("MyManagedPolicy", policy.Name)
		self.assertEqual("/my/custom/path", policy.Path)
		self.assertEqual(sample_policy_a, policy.Policy)


class WhenParsingAManagedPolicyThatIsNotAttachedWithNoNameOrPath(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_user_and_policy(self):
		template = load({
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=1)

		policy = self.orphaned_policies[0]
		self.assertEqual("ManagedPolicy", policy.Name)
		self.assertEqual("/", policy.Path)
		self.assertEqual(sample_policy_a, policy.Policy)


class WhenParsingAManagedPolicyAttachedToRoleFromThePolicy(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_roles_with_attached_policy(self):
		template = load({
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'Roles': [
							{'Ref': 'RoleA'},
							{'Ref': 'RoleB'}
						]
					}
				},
				'RoleA': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				},
				'RoleB': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=2)

		role_a = self.roles[0]
		self.assertEqual(1, len(role_a.Policies))
		self.assertTrue(has_policy(role_a, "ManagedPolicy", sample_policy_a))

		role_b = self.roles[1]
		self.assertEqual(1, len(role_b.Policies))
		self.assertTrue(has_policy(role_b, "ManagedPolicy", sample_policy_a))

		# ensure they are two separate roles
		self.assertNotEqual(role_a.RoleName, role_b.RoleName)


class WhenParsingAManagedPolicyAttachedToAUserFromThePolicy(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_users_with_attached_policy(self):
		template = load({
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'Users': [
							{'Ref': 'UserA'},
							{'Ref': 'UserB'}
						]
					}
				},
				'UserA': {
					'Type': 'AWS::IAM::User'
				},
				'UserB': {
					'Type': 'AWS::IAM::User'
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_users=2)

		user_a = self.users[0]
		self.assertEqual(1, len(user_a.Policies))
		self.assertTrue(has_policy(user_a, "ManagedPolicy", sample_policy_a))

		user_b = self.users[1]
		self.assertEqual(1, len(user_b.Policies))
		self.assertTrue(has_policy(user_b, "ManagedPolicy", sample_policy_a))

		# ensure they are not the same user
		self.assertNotEqual(user_a.UserName, user_b.UserName)


class WhenParsingAManagedPolicyAttachedToAGroupFromThePolicy(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_groups_with_attached_policy(self):
		template = load({
			'Resources': {
				'ManagedPolicy': {
					'Type': 'AWS::IAM::ManagedPolicy',
					'Properties': {
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'Groups': [
							{'Ref': 'GroupA'},
							{'Ref': 'GroupB'}
						]
					}
				},
				'GroupA': {
					'Type': 'AWS::IAM::Group'
				},
				'GroupB': {
					'Type': 'AWS::IAM::Group'
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=2)

		group_a = self.groups[0]
		self.assertEqual(1, len(group_a.Policies))
		self.assertTrue(has_policy(group_a, "ManagedPolicy", sample_policy_a))

		group_b = self.groups[1]
		self.assertEqual(1, len(group_b.Policies))
		self.assertTrue(has_policy(group_b, "ManagedPolicy", sample_policy_a))

		# ensure they are not the same user
		self.assertNotEqual(group_a.GroupName, group_b.GroupName)
