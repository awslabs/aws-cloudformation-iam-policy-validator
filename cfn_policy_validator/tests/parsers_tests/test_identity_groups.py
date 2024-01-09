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

from cfn_policy_validator.tests.parsers_tests.test_identity import has_policy, \
	sample_policy_a, sample_policy_b, IdentityParserTest, aws_lambda_basic_execution_response, \
	aws_lambda_basic_execution_version_response, aws_lambda_execute_response, aws_lambda_execute_version_response


class WhenParsingAnIAMGroupWithAName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_group(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Group',
					'Properties': {
						'Path': '/custom/group/path',
						'GroupName': 'MyGroupName'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual("MyGroupName", group.GroupName)
		self.assertEqual("/custom/group/path", group.GroupPath)
		self.assertEqual(0, len(group.Policies))


class WhenParsingAnIAMGroupWithNoName(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_group(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Group',
					'Properties': {
						'Path': '/custom/group/path'
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual("ResourceA", group.GroupName)
		self.assertEqual("/custom/group/path", group.GroupPath)
		self.assertEqual(0, len(group.Policies))


class WhenParsingAnIAMPolicyAttachedToAGroup(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_group_and_policy(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual("ResourceA", group.GroupName)
		self.assertEqual("/", group.GroupPath)
		self.assertEqual(2, len(group.Policies))

		self.assertTrue(has_policy(group, 'PolicyA', sample_policy_a))
		self.assertTrue(has_policy(group, 'PolicyB', sample_policy_b))


class WhenParsingAnIAMGroupWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a group
	@mock_identity_parser_setup()
	def test_returns_a_group_with_references_resolved(self):
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
				'GroupPath': {},
				'GroupName': {},
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
					'Type': 'AWS::IAM::Group',
					'Properties': {
						'Path': {'Ref': 'GroupPath'},
						'GroupName': {'Ref': 'GroupName'},
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
			'GroupPath': '/custom/group/path',
			'GroupName': 'CustomGroupName',
			'Resource': 'my_resource/*'
		})

		self.parse(template, account_config)
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual("CustomGroupName", group.GroupName)
		self.assertEqual("/custom/group/path", group.GroupPath)

		expected_inline_policy = inline_policy.copy()
		expected_inline_policy['Statement'][0]['Resources'] = 'my_resource/*'

		self.assertEqual(2, len(group.Policies))
		self.assertTrue(has_policy(group, 'Policy1', expected_inline_policy))
		self.assertTrue(has_policy(group, "ManagedPolicy", sample_policy_a))


class WhenParsingManagedPoliciesAttachedToAGroupFromTheGroup(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_a_group_with_attached_policies(self):
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
				'Group': {
					'Type': 'AWS::IAM::Group',
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
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual(2, len(group.Policies))
		self.assertTrue(has_policy(group, "ManagedPolicyA", sample_policy_a))
		self.assertTrue(has_policy(group, "ManagedPolicyB", sample_policy_b))


# note that the DependsOn is required here, otherwise the managed policy would not exist when the group attempts to find it
class WhenParsingManagedPoliciesAttachedToAGroupFromTheGroupAndArnIsNotRef(IdentityParserTest):
	@mock_identity_parser_setup()
	def test_returns_groups_with_attached_policies(self):
		template = load({
			'Resources': {
				'Group': {
					'Type': 'AWS::IAM::Group',
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
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual(1, len(group.Policies))
		self.assertTrue(has_policy(group, "MyManagedPolicy", sample_policy_a))


class WhenParsingManagedPolicyAttachedToAGroupAndThePolicyIsAWSManaged(IdentityParserTest):
	@offline_only
	@mock_identity_parser_setup(
		iam=[
			aws_lambda_basic_execution_response(),
			aws_lambda_basic_execution_version_response(),
			aws_lambda_execute_response(),
			aws_lambda_execute_version_response()
		]
	)
	def test_returns_group_with_attached_policies(self):
		template = load({
			'Resources': {
				'Group': {
					'Type': 'AWS::IAM::Group',
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
		self.assertResults(number_of_groups=1)

		group = self.groups[0]
		self.assertEqual(2, len(group.Policies))
		self.assertTrue(has_policy(group, "AWSLambdaBasicExecutionRole", sample_policy_a, '/service-role/'))
		self.assertTrue(has_policy(group, "AWSLambdaExecute", sample_policy_b, '/'))


class WhenParsingManagedPolicyAttachedToAGroupAndThePolicyDoesNotExistInTemplateOrAWS(unittest.TestCase):
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
				'Group': {
					'Type': 'AWS::IAM::Group',
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


class WhenParsingAnIAMGroupAndValidatingSchema(unittest.TestCase):
	@mock_identity_parser_setup()
	def test_with_invalid_group_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
				'Properties': {
					'GroupName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.GroupName', 'string', "['Invalid']"),  str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_path_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
				'Properties': {
					'Path': {'abc': 'def'}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Path', 'string', "{'abc': 'def'}"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policies_type(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Group',
					'Properties': {
						'Policies': 'PolicyA'
					}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual("'PolicyA' is not of type 'array', Path: Resources.ResourceA.Properties.Policies", str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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

		self.assertEqual(required_property_error('PolicyDocument', 'Resources.ResourceA.Properties.Policies.0'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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

		self.assertEqual("'Invalid' is not of type 'object', Path: Resources.ResourceA.Properties.Policies.0.PolicyDocument", str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_no_policy_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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

		self.assertEqual(required_property_error('PolicyName', 'Resources.ResourceA.Properties.Policies.0'), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policy_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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

		self.assertEqual("['Invalid'] is not of type 'string', Path: Resources.ResourceA.Properties.Policies.0.PolicyName", str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_policies_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
				'Properties': {
					'Policies': ['PolicyA']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual("'PolicyA' is not of type 'object', Path: Resources.ResourceA.Properties.Policies.0", str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_arns_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
				'Properties': {
					'ManagedPolicyArns': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ManagedPolicyArns', 'array', "'Invalid'"), str(cm.exception))

	@mock_identity_parser_setup()
	def test_with_invalid_managed_policy_arn_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Group',
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
				'Type': 'AWS::IAM::Group',
				'Properties': {
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
				'Type': 'AWS::IAM::Group',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')
