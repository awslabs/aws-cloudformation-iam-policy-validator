"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.parsers.output import Resource, Policy

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources
from cfn_policy_validator.application_error import ApplicationError


secrets_manager_policy_with_no_reference = {
	"Statement": [{
		"Sid": "grant-1234-delete",
		"Effect": "Allow",
		"Principal": {
			"AWS": "111122223333"
		},
		"Action": ["secretsmanager:DeleteSecret"],
		"Resource": "*"
	}]
}


secrets_manager_policy_with_reference = {
	"Statement": [{
		"Sid": "grant-1234-delete",
		"Effect": "Allow",
		"Principal": {
			"AWS": "111122223333"
		},
		"Action": ["secretsmanager:DeleteSecret"],
		"Resource": {"Ref": "SecretA"}
	}]
}


class WhenParsingASecretsManagerResourcePolicyAndValidatingSchema(unittest.TestCase):
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	def test_with_no_resource_policy(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': f"arn:aws:secretsmanager:us-west-2:111122223333:secret:123456"
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('ResourcePolicy', 'ResourceA.Properties'), str(cm.exception))

	def test_with_invalid_resource_policy_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': "arn:aws:secretsmanager:us-west-2:111122223333:secret:123456",
					'ResourcePolicy': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.ResourcePolicy', 'object', "['Invalid']"), str(cm.exception))

	def test_with_no_secret_id(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('SecretId', 'ResourceA.Properties'), str(cm.exception))

	def test_with_invalid_secret_id_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': ["Invalid"],
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.SecretId', 'string', "['Invalid']"), str(cm.exception))

	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': "arn:aws:secretsmanager:us-west-2:111122223333:secret:123456",
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference),
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': "arn:aws:secretsmanager:us-west-2:111122223333:secret:123456",
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference),
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingASecretsManagerResourcePolicyWithInvalidSecretId(unittest.TestCase):
	def test_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::SecretsManager::ResourcePolicy',
					'Properties': {
						# a valid secret ARN must have secret: in the ARN
						'SecretId': "arn:aws:secretsmanager:us-west-2:111122223333:123456",
						'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference)
					}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual("Invalid value for ResourceA.Properties.SecretId. Must be a valid Secret ARN. "
						 "SecretId value: arn:aws:secretsmanager:us-west-2:111122223333:123456", str(cm.exception))


class WhenParsingASecretsManagerResourcePolicy(unittest.TestCase):
	def test_returns_a_resource(self):
		secret_name = 'aes128-1a2b3c'
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': f"arn:aws:secretsmanager:us-west-2:111122223333:secret:{secret_name}",
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_no_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy = Policy("ResourcePolicy", secrets_manager_policy_with_no_reference)
		expected_resource_a = Resource(secret_name, "AWS::SecretsManager::Secret", expected_policy)
		self.assertIn(expected_resource_a, resources)


class WhenParsingASecretsManagerPolicyWithReferencesInEachField(unittest.TestCase):
	# this is a test to ensure that each field is being evaluated for references in a role
	def test_returns_a_resource_with_references_resolved(self):
		template = load_resources({
			'SecretA': {
				'Type': 'AWS::SecretsManager::Secret',
				'Properties': {
					'SecretString': 'secret'
				}
			},
			'ResourceA': {
				'Type': 'AWS::SecretsManager::ResourcePolicy',
				'Properties': {
					'SecretId': {'Ref': 'SecretA'},
					'ResourcePolicy': copy.deepcopy(secrets_manager_policy_with_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy_doc = copy.deepcopy(secrets_manager_policy_with_reference)
		expected_policy_doc['Statement'][0]['Resource'] = f'arn:aws:secretsmanager:{account_config.region}:{account_config.account_id}:secret:SecretA'

		expected_policy = Policy("ResourcePolicy", expected_policy_doc)
		expected_resource_a = Resource("SecretA", "AWS::SecretsManager::Secret", expected_policy)
		self.assertIn(expected_resource_a, resources)
