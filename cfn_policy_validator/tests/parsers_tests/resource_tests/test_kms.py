"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.parsers.output import Resource, Policy
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources
from cfn_policy_validator.application_error import ApplicationError


kms_policy_with_no_reference = {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "Allow use of the key",
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::111122223333:user/CMKUser"},
		"Action": [
			"kms:DescribeKey",
			"kms:GetPublicKey",
			"kms:Sign",
			"kms:Verify"
		],
		"Resource": "*"
	}]
}


kms_policy_with_reference = {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "Allow use of the key",
		"Effect": "Allow",
		"Principal": {"AWS": {"Fn::GetAtt": ["SomeUser", "Arn"]}},
		"Action": [
			"kms:DescribeKey",
			"kms:GetPublicKey",
			"kms:Sign",
			"kms:Verify"
		],
		"Resource": "*"
	}]
}


class WhenParsingAKmsKeyPolicyAndValidatingSchema(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::KMS::Key'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_key_policy(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::KMS::Key',
				'Properties': {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('KeyPolicy', 'Resources.ResourceA.Properties'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_key_policy(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::KMS::Key',
				'Properties': {
					'KeyPolicy': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.KeyPolicy', 'object', "['Invalid']"), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::KMS::Key',
				'Properties': {
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}},
					'KeyPolicy': copy.deepcopy(kms_policy_with_no_reference)
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_node_evaluator_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::KMS::Key',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'},
					'KeyPolicy': copy.deepcopy(kms_policy_with_no_reference)
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAKmsKeyPolicy(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::KMS::Key',
					'Properties': {
						'KeyPolicy': copy.deepcopy(kms_policy_with_no_reference)
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy = Policy("KeyPolicy", kms_policy_with_no_reference)
		expected_resource_a = Resource("ResourceA", "AWS::KMS::Key", expected_policy)
		self.assertIn(expected_resource_a, resources)


class WhenParsingAKmsKeyPolicyWithReferencesInEachField(unittest.TestCase):
	# this is a test to ensure that each field is being evaluated for references in a key
	@mock_node_evaluator_setup()
	def test_returns_a_resource_with_references_resolved(self):
		template = load({
			'Resources': {
				'SomeUser': {
					'Type': 'AWS::IAM::User'
				},
				'ResourceA': {
					'Type': 'AWS::KMS::Key',
					'Properties': {
						'KeyPolicy': copy.deepcopy(kms_policy_with_reference)
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy_doc = copy.deepcopy(kms_policy_with_reference)
		expected_policy_doc['Statement'][0]['Principal'] = {'AWS': f'arn:aws:iam::{account_config.account_id}:user/SomeUser'}

		expected_policy = Policy("KeyPolicy", expected_policy_doc)
		expected_resource_a = Resource("ResourceA", "AWS::KMS::Key", expected_policy)
		self.assertIn(expected_resource_a, resources)
