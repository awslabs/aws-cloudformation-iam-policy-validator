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


sns_policy_with_no_reference = {
	"Statement": [{
		"Sid": "grant-1234-publish",
		"Effect": "Allow",
		"Principal": {
			"AWS": "111122223333"
		},
		"Action": ["sns:Publish"],
		"Resource": "arn:aws:sns:us-east-2:444455556666:MyTopic"
	}]
}


sns_policy_with_reference = {
	"Statement": [{
		"Sid": "grant-1234-publish",
		"Effect": "Allow",
		"Principal": {
			"AWS": "111122223333"
		},
		"Action": ["sns:Publish"],
		"Resource": {"Ref": "TestTopicA"}
	}]
}


class WhenParsingAnSnsTopicPolicyAndValidatingSchema(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						'arn:aws:sns:us-east-1:123456:MyTopic',
						'arn:aws:sns:us-east-1:123456:MyTopic2'
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'Resources.ResourceA.Properties'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						'arn:aws:sns:us-east-1:123456:MyTopic',
						'arn:aws:sns:us-east-1:123456:MyTopic2'
					],
					'PolicyDocument': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.PolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_topics(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Topics', 'Resources.ResourceA.Properties'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_topics_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': {
						'arn:aws:sns:us-east-1:123456:MyTopic': 1,
						'arn:aws:sns:us-east-1:123456:MyTopic2': 2
					},
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Topics', 'array',
											 "{'arn:aws:sns:us-east-1:123456:MyTopic': 1, 'arn:aws:sns:us-east-1:123456:MyTopic2': 2}"),
						 str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_topics_items(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [],
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual('[] is too short, Path: Resources.ResourceA.Properties.Topics', str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_topics_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [{
						'arn:aws:sns:us-east-1:123456:MyTopic': 1,
						'arn:aws:sns:us-east-1:123456:MyTopic2': 2
					}],
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Topics.0', 'string',
											 "{'arn:aws:sns:us-east-1:123456:MyTopic': 1, 'arn:aws:sns:us-east-1:123456:MyTopic2': 2}"),
						str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						'arn:aws:sns:us-east-1:123456:MyTopic',
						'arn:aws:sns:us-east-1:123456:MyTopic2'
					],
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference),
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	@mock_node_evaluator_setup()
	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						'arn:aws:sns:us-east-1:123456:MyTopic',
						'arn:aws:sns:us-east-1:123456:MyTopic2'
					],
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference),
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnSnsTopicPolicy(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						'arn:aws:sns:us-east-1:123456:MyTopic',
						'arn:aws:sns:us-east-1:123456:MyTopic2'
					],
					'PolicyDocument': copy.deepcopy(sns_policy_with_no_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy = Policy("TopicPolicy", sns_policy_with_no_reference)
		expected_resource_a = Resource("MyTopic", "AWS::SNS::Topic", expected_policy)
		self.assertIn(expected_resource_a, resources)

		expected_policy = Policy("TopicPolicy", sns_policy_with_no_reference)
		expected_resource_b = Resource("MyTopic2", "AWS::SNS::Topic", expected_policy)
		self.assertIn(expected_resource_b, resources)


class WhenParsingAnSnsTopicPolicyWithReferencesInEachField(unittest.TestCase):
	# this is a test to ensure that each field is being evaluated for references in a role
	@mock_node_evaluator_setup()
	def test_returns_a_resource_with_references_resolved(self):
		template = load_resources({
			'TestTopicA': {
				'Type': 'AWS::SNS::Topic'
			},
			'TestTopicB': {
				'Type': 'AWS::SNS::Topic',
				'Properties': {
					'TopicName': 'MyTestTopicB'
				}
			},
			'ResourceA': {
				'Type': 'AWS::SNS::TopicPolicy',
				'Properties': {
					'Topics': [
						{'Ref': 'TestTopicA'},
						{'Ref': 'TestTopicB'}
					],
					'PolicyDocument': copy.deepcopy(sns_policy_with_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy_doc = copy.deepcopy(sns_policy_with_reference)
		expected_policy_doc['Statement'][0]['Resource'] = f'arn:aws:sns:{account_config.region}:{account_config.account_id}:TestTopicA'

		expected_policy = Policy("TopicPolicy", expected_policy_doc)
		expected_resource_a = Resource("TestTopicA", "AWS::SNS::Topic", expected_policy)
		self.assertIn(expected_resource_a, resources)

		# for SNS topics there is no custom logic to map the TopicName to the ARN output, so it will default
		# back to the resource name (TestTopicB).
		expected_policy = Policy("TopicPolicy", expected_policy_doc)
		expected_resource_b = Resource("TestTopicB", "AWS::SNS::Topic", expected_policy)
		self.assertIn(expected_resource_b, resources)
