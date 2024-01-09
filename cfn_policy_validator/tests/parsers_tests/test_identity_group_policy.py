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


class WhenParsingAGroupPolicyAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'Resources.GroupPolicy'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_name(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'GroupName': 'MyGroup'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyName', 'Resources.GroupPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_name_type(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyName': ['Invalid'],
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'GroupName': 'MyGroup'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.GroupPolicy.Properties.PolicyName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyName': 'MyPolicy',
					'GroupName': 'MyGroup'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'Resources.GroupPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': 'Invalid',
					'GroupName': 'MyGroup'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.GroupPolicy.Properties.PolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_group_name(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('GroupName', 'Resources.GroupPolicy.Properties'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_group_name_type(self):
		template = load_resources({
			'GroupPolicy': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'GroupName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.GroupPolicy.Properties.GroupName', 'string', "['Invalid']"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'GroupName': 'MyGroup'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_identity_parser_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::GroupPolicy',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'},
					'PolicyName': 'PolicyA',
					'PolicyDocument': copy.deepcopy(sample_policy_a),
					'GroupName': 'MyGroup'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAGroupPolicyWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a group policy
	@mock_identity_parser_setup()
	def test_returns_a_group_with_references_resolved(self):
		group_policy = {
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
				'GroupPolicy': {
					'Type': 'AWS::IAM::GroupPolicy',
					'Properties': {
						'PolicyDocument': group_policy,
						'PolicyName': {'Ref': 'Name'},
						'GroupName': {'Ref': 'Group'}
					}
				},
				'Group': {
					'Type': 'AWS::IAM::Group'
				}
			}
		}, {
			'Name': 'PolicyName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		expected_group_policy = group_policy.copy()
		expected_group_policy['Statement'][0]['Resource'] = 'my_resource/*'

		group = self.groups[0]
		self.assertEqual(1, len(group.Policies))
		self.assertTrue(has_policy(group, 'PolicyName', expected_group_policy))


class WhenParsingAGroupPolicyAttachedToGroup(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_group_with_attached_policy(self):
		template = load({
			'Resources': {
				'GroupPolicy': {
					'Type': 'AWS::IAM::GroupPolicy',
					'Properties': {
						'PolicyName': 'GroupPolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'GroupName': {'Ref': 'GroupA'}
					}
				},
				'GroupA': {
					'Type': 'AWS::IAM::Group'
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		group_a = self.groups[0]
		self.assertEqual(1, len(group_a.Policies))
		self.assertTrue(has_policy(group_a, "GroupPolicy", sample_policy_a))


class WhenParsingAPolicyThatIsAttachedToAnExternalGroup(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_an_orphaned_policy(self):
		template = load({
			'Parameters': {
				'GroupA': {}
			},
			'Resources': {
				'Policy': {
					'Type': 'AWS::IAM::GroupPolicy',
					'Properties': {
						'PolicyName': 'MyPolicy',
						'PolicyDocument': copy.deepcopy(sample_policy_a),
						'GroupName': {'Ref': 'GroupA'}
					}
				}
			}
		}, {
			'GroupA': 'MyGroupA'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=1)

		policy = self.orphaned_policies[0]
		self.assertEqual("MyPolicy", policy.Name)
		self.assertEqual("/", policy.Path)
		self.assertEqual(sample_policy_a, policy.Policy)


class WhenParsingMultipleGroupPoliciesWithTheSameName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_all_inline_policies(self):
		group_policy_a = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'ec2:RunInstances',
					'Resource': "*"
				}
			]
		}

		group_policy_b = {
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
				'GroupPolicyA': {
					'Type': 'AWS::IAM::GroupPolicy',
					'Properties': {
						'PolicyDocument': group_policy_a,
						'PolicyName': 'Policy',
						'GroupName': 'MyExternalGroup'
					}
				},
				'GroupPolicyB': {
					'Type': 'AWS::IAM::GroupPolicy',
					'Properties': {
						'PolicyDocument': group_policy_b,
						'PolicyName': 'Policy',
						'GroupName': 'MyExternalGroup'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_orphaned_policies=2)

		policy = self.orphaned_policies[0]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(group_policy_a, policy.Policy)

		policy = self.orphaned_policies[1]
		self.assertEqual("Policy", policy.Name)
		self.assertEqual(group_policy_b, policy.Policy)
