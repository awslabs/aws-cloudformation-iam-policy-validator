"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from unittest.mock import patch, MagicMock

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity import IdentityParser
from cfn_policy_validator.parsers import identity

from cfn_policy_validator.tests.parsers_tests.test_identity import has_policy, assume_role_policy_doc, \
	sample_policy_a, sample_policy_b, get_policy_side_effect, get_policy_version_side_effect, IdentityParserTest


class WhenParsingAnIAMRoleAndValidatingSchema(unittest.TestCase):
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	def test_with_no_assume_role_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('AssumeRolePolicyDocument', 'ResourceA.Properties'),
						 str(cm.exception))

	def test_with_invalid_assume_role_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.AssumeRolePolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	def test_with_invalid_path_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'Path': {'abc': 'def'},
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.Path', 'string', "{'abc': 'def'}"),
						 str(cm.exception))

	def test_with_invalid_role_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'RoleName': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.RoleName', 'string', "['Invalid']"), str(cm.exception))

	def test_with_valid_role_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'RoleName': 'role.a.b.c'
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'No validation error raised')

	def test_with_invalid_role_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'RoleName': 'role1!!!!'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(r"'role1!!!!' does not match '^([\\w+=,.@-]+)$', Path: ResourceA.Properties.RoleName", str(cm.exception))

	def test_with_invalid_policies_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'Policies': 'PolicyA'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.Policies', 'array', "'PolicyA'"), str(cm.exception))

	def test_with_invalid_policies_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'Policies': ['PolicyA']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.Policies.0', 'object', "'PolicyA'"), str(cm.exception))

	def test_with_no_policy_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'Policies': [
						{
							'PolicyDocument': copy.deepcopy(sample_policy_a)
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyName', 'ResourceA.Properties.Policies.0'), str(cm.exception))

	def test_with_invalid_policies_policy_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
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

		self.assertEqual(expected_type_error('ResourceA.Properties.Policies.0.PolicyName', 'string', "['Invalid']"),
			str(cm.exception))

	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'Policies': [
						{
							'PolicyName': 'PolicyA'
						}
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'ResourceA.Properties.Policies.0'), str(cm.exception))

	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
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
			expected_type_error('ResourceA.Properties.Policies.0.PolicyDocument', 'object', "'Invalid'"),
			str(cm.exception))

	def test_with_invalid_managed_policy_arns_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'ManagedPolicyArns': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.ManagedPolicyArns', 'array', "'Invalid'"),
						 str(cm.exception))

	def test_with_invalid_managed_policy_arns_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'ManagedPolicyArns': [['Invalid']]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			IdentityParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.ManagedPolicyArns.0', 'string', "['Invalid']"), str(cm.exception))

	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::IAM::Role',
				'Properties': {
					'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		IdentityParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnIAMRoleWithAName(IdentityParserTest):
	def test_returns_a_role(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'Path': '/custom/path',
						'RoleName': 'MyRole',
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual("MyRole", role.RoleName)
		self.assertEqual("/custom/path", role.RolePath)
		self.assertEqual(assume_role_policy_doc, role.TrustPolicy)
		self.assertEqual(0, len(role.Policies))


class WhenParsingAnIAMRoleWithNoNameOrPath(IdentityParserTest):
	def test_returns_a_role(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual("ResourceA", role.RoleName)
		self.assertEqual("/", role.RolePath)
		self.assertEqual(assume_role_policy_doc, role.TrustPolicy)
		self.assertEqual(0, len(role.Policies))

	# Role Name length max is 64 characters
	def test_long_role_name_is_truncated(self):
		role_name = 'ResourceA123456789123456789123456789123456789123456789123456789123456789'
		template = load({
			'Resources': {
				'ResourceA123456789123456789123456789123456789123456789123456789123456789': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc)
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual(role_name[:64], role.RoleName)
		self.assertEqual("/", role.RolePath)
		self.assertEqual(assume_role_policy_doc, role.TrustPolicy)
		self.assertEqual(0, len(role.Policies))


class WhenParsingAnIAMPolicyAttachedToARole(IdentityParserTest):
	def test_returns_a_role_and_policy(self):
		template = load({
			'Resources': {
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
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
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual("Role", role.RoleName)
		self.assertEqual("/", role.RolePath)
		self.assertEqual(assume_role_policy_doc, role.TrustPolicy)
		self.assertEqual(2, len(role.Policies))

		self.assertTrue(has_policy(role, 'PolicyA', sample_policy_a))
		self.assertTrue(has_policy(role, 'PolicyB', sample_policy_b))


class WhenParsingAnIAMRoleWithReferencesInEachField(IdentityParserTest):
	# this is a test to ensure that each field is being evaluated for references in a role
	def test_returns_a_role_with_references_resolved(self):
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
				'RolePath': {},
				'RoleName': {},
				'ServiceName': {},
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
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'Path': {'Ref': 'RolePath'},
						'RoleName': {'Ref': 'RoleName'},
						'AssumeRolePolicyDocument': {
							'Version': '2012-10-17',
							'Statement': [
								{
									'Effect': 'Allow',
									'Principal': {
										'Service': {'Ref': 'ServiceName'}
									},
									'Action': 'sts:AssumeRole'
								}
							]
						},
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
		   'RolePath': '/custom/role/path/',
		   'RoleName': 'CustomRoleName',
		   'ServiceName': 'customservice.amazonaws.com',
		   'Resource': 'my_resource/*'
	   })

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual("CustomRoleName", role.RoleName)
		self.assertEqual("/custom/role/path/", role.RolePath)
		self.assertEqual('customservice.amazonaws.com', role.TrustPolicy['Statement'][0]['Principal']['Service'])

		expected_inline_policy = inline_policy.copy()
		expected_inline_policy['Statement'][0]['Resources'] = 'my_resource/*'

		self.assertEqual(2, len(role.Policies))
		self.assertTrue(has_policy(role, 'Policy1', expected_inline_policy))
		self.assertTrue(has_policy(role, "ManagedPolicy", sample_policy_a))


class WhenParsingManagedPoliciesAttachedToARoleFromTheRole(IdentityParserTest):
	def test_returns_roles_with_attached_policies(self):
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
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
						'ManagedPolicyArns': [
							{'Ref': 'ManagedPolicyA'},
							{'Ref': 'ManagedPolicyB'}
						]
					}
				}
			}
		})

		self.parse(template, account_config)
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual(2, len(role.Policies))
		self.assertTrue(has_policy(role, "ManagedPolicyA", sample_policy_a))
		self.assertTrue(has_policy(role, "ManagedPolicyB", sample_policy_b))


# note that the DependsOn is required here, otherwise the managed policy would not exist when the role attempts to find it
class WhenParsingManagedPoliciesAttachedToARoleFromTheRoleAndArnIsNotRef(IdentityParserTest):
	def test_returns_roles_with_attached_policies(self):
		template = load({
			'Resources': {
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
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
		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual(1, len(role.Policies))
		self.assertTrue(has_policy(role, "MyManagedPolicy", sample_policy_a))


class WhenParsingManagedPolicyAttachedToARoleAndThePolicyIsAWSManaged(IdentityParserTest):
	def test_returns_role_with_attached_policies(self):
		template = load({
			'Resources': {
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
						'ManagedPolicyArns': [
							'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
							'arn:aws:iam::aws:policy/AWSLambdaExecute'
						]
					}
				}
			}
		})

		mock_client = MagicMock()
		mock_client.get_policy = MagicMock(side_effect=get_policy_side_effect)
		mock_client.get_policy_version = MagicMock(side_effect=get_policy_version_side_effect)

		with patch.object(identity.client, 'build', return_value=mock_client):
			self.parse(template, account_config)

		self.assertResults(number_of_roles=1)

		role = self.roles[0]
		self.assertEqual(2, len(role.Policies))
		self.assertTrue(has_policy(role, "AWSLambdaBasicExecutionRole", sample_policy_a, '/service-role/'))
		self.assertTrue(has_policy(role, "AWSLambdaExecute", sample_policy_b, '/'))


class WhenParsingManagedPolicyAttachedToARoleAndThePolicyDoesNotExistInTemplateOrAWS(unittest.TestCase):
	def test_throws_exception(self):
		template = load({
			'Resources': {
				'Role': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
						'ManagedPolicyArns': [
							'arn:aws:iam::aws:policy/DoesNotExist'
						]
					}
				}
			}
		})

		import boto3
		client = boto3.client('iam')

		def get_non_existent_policy(*, PolicyArn):
			if PolicyArn == 'arn:aws:iam::aws:policy/DoesNotExist':
				raise client.exceptions.NoSuchEntityException({}, "")

		mock_client = MagicMock()
		mock_client.get_policy = MagicMock(side_effect=get_non_existent_policy)
		mock_client.exceptions.NoSuchEntityException = client.exceptions.NoSuchEntityException

		with patch.object(identity.client, 'build', return_value=mock_client):
			with self.assertRaises(ApplicationError) as cm:
				IdentityParser.parse(template, account_config)

			self.assertEqual('Could not find managed policy with arn:aws:iam::aws:policy/DoesNotExist in template '
							 'or in environment.', str(cm.exception))
