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


sqs_policy_with_no_reference = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": ["111122223333"]
		},
		"Action": "sqs:SendMessage",
		"Resource": "arn:aws:sqs:us-east-2:444455556666:queue1"
	}]
}


sqs_policy_with_reference = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": ["111122223333"]
		},
		"Action": "sqs:SendMessage",
		"Resource": {"Fn::GetAtt": ["TestQueueA", "Arn"]}
	}]
}


class WhenParsingAnSqsQueuePolicyAndValidatingSchema(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_policy_document(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue',
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
					]
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('PolicyDocument', 'ResourceA.Properties'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_policy_document_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue',
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
					],
					'PolicyDocument': 'Invalid'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.PolicyDocument', 'object', "'Invalid'"), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_queues(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Queues', 'ResourceA.Properties'), str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_queues_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': {
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue': 1,
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue': 2
					},
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.Queues', 'array',
											 "{'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue': 1, "
											 "'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue': 2}"),
						 str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_no_queues_items(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual('[] is too short, Path: ResourceA.Properties.Queues', str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_queues_item_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [{
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue': 1,
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue': 2
					}],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('ResourceA.Properties.Queues.0', 'string',
											 "{'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue': 1, "
											 "'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue': 2}"),
						 str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue',
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
					],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference),
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
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue',
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
					],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference),
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnSqsQueueWithInvalidQueueURL(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::SQS::QueuePolicy',
					'Properties': {
						'Queues': [
							'https://sqs.us-east-1.amazonaws.com/MyTestQueue',
							'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
						],
						'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
					}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual("Invalid queue URL. Unable to parse name from URL. Invalid value: "
						 "\"https://sqs.us-east-1.amazonaws.com/MyTestQueue\"", str(cm.exception))


class WhenParsingAnSqsQueuePolicy(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						'https://sqs.us-east-1.amazonaws.com/123456/MyTestQueue',
						'https://sqs.us-east-1.amazonaws.com/123456/MySecondTestQueue'
					],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_no_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy = Policy("QueuePolicy", sqs_policy_with_no_reference)
		expected_resource_a = Resource("MyTestQueue", "AWS::SQS::Queue", expected_policy)
		self.assertIn(expected_resource_a, resources)

		expected_policy = Policy("QueuePolicy", sqs_policy_with_no_reference)
		expected_resource_b = Resource("MySecondTestQueue", "AWS::SQS::Queue", expected_policy)
		self.assertIn(expected_resource_b, resources)


class WhenParsingAnSqsQueuePolicyWithReferencesInEachField(unittest.TestCase):
	# this is a test to ensure that each field is being evaluated for references in a queue
	@mock_node_evaluator_setup()
	def test_returns_a_resource_with_references_resolved(self):
		template = load_resources({
			'TestQueueA': {
				'Type': 'AWS::SQS::Queue'
			},
			'TestQueueB': {
				'Type': 'AWS::SQS::Queue',
				'Properties': {
					'QueueName': 'MyTestQueueB'
				}
			},
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						{'Ref': 'TestQueueA'},
						{'Ref': 'TestQueueB'}
					],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy_doc = copy.deepcopy(sqs_policy_with_reference)
		expected_policy_doc['Statement'][0]['Resource'] = f'arn:aws:sqs:{account_config.region}:{account_config.account_id}:TestQueueA'

		expected_policy = Policy("QueuePolicy", expected_policy_doc)
		expected_resource_a = Resource("TestQueueA", "AWS::SQS::Queue", expected_policy)
		self.assertIn(expected_resource_a, resources)

		expected_policy = Policy("QueuePolicy", expected_policy_doc)
		expected_resource_b = Resource("MyTestQueueB", "AWS::SQS::Queue", expected_policy)
		self.assertIn(expected_resource_b, resources)


class WhenParsingAnSqsQueuePolicyWithQueueThatHasExplicitName(unittest.TestCase):
	# this is a test to ensure that each field is being evaluated for references in a queue
	@mock_node_evaluator_setup()
	def test_returns_a_resource_with_references_resolved(self):
		template = load_resources({
			'TestQueueA': {
				'Type': 'AWS::SQS::Queue',
				'Properties': {
					'QueueName': 'CustomQueueName'
				}
			},
			'ResourceA': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						{'Ref': 'TestQueueA'}
					],
					'PolicyDocument': copy.deepcopy(sqs_policy_with_reference)
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy_doc = copy.deepcopy(sqs_policy_with_reference)
		expected_policy_doc['Statement'][0]['Resource'] = f'arn:aws:sqs:{account_config.region}:{account_config.account_id}:CustomQueueName'

		expected_policy = Policy("QueuePolicy", expected_policy_doc)
		expected_resource_a = Resource("CustomQueueName", "AWS::SQS::Queue", expected_policy)
		self.assertIn(expected_resource_a, resources)
