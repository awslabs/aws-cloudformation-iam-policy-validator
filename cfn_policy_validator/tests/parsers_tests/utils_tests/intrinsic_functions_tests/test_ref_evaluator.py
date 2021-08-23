"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.utils import load, account_config, expected_type_error, load_resources


class WhenEvaluatingAPolicyWithARefToAccountId(unittest.TestCase):
	def test_returns_the_account_id(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						"Ref": "AWS::AccountId"
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(account_config.account_id, result)


class WhenEvaluatingAPolicyWithARefToPartition(unittest.TestCase):
	def test_returns_the_partition(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						"Ref": "AWS::Partition"
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'aws')


class WhenEvaluatingAPolicyWithARefToRegion(unittest.TestCase):
	def test_returns_the_region(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						"Ref": "AWS::Region"
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(account_config.region, result)


class WhenEvaluatingAPolicyWithARefToStackName(unittest.TestCase):
	def test_returns_the_partition(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						"Ref": "AWS::StackName"
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'StackName')


class WhenEvaluatingAPolicyWithARefToAnArn(unittest.TestCase):
	def test_returns_the_arn(self):
		template = load_resources({
			'SNSTopic': {
				'Type': "AWS::SNS::Topic"
			},
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Ref': 'SNSTopic'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(f'arn:aws:sns:{account_config.region}:{account_config.account_id}:SNSTopic', result)


class WhenEvaluatingAPolicyWithARefToAResource(unittest.TestCase):
	def test_returns_the_resource_name(self):
		template = load({
			'Resources': {
				'IAMRole': {
					'Type': "AWS::IAM::Role",
					'Properties': {}
				},
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Ref': 'IAMRole'
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'IAMRole')


class WhenEvaluatingAPolicyWithARefToAParameter(unittest.TestCase):
	def test_returns_the_parameter_value(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Ref': 'Param1'
						}
					}
				}
			}
		})

		parameters = {
			'Param1': 'Param1Value'
		}

		node_evaluator = NodeEvaluator(template, account_config, parameters)

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'Param1Value')


class WhenEvaluatingTemplateWithANestedRef(unittest.TestCase):
	def test_returns_the_nested_value(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Role',
					'Properties': {
						'RoleName': {
							'Ref': 'Param1'
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Ref': 'ResourceA'
						}
					}
				}
			}
		})

		parameters = {
			'Param1': 'Param1Value'
		}

		node_evaluator = NodeEvaluator(template, account_config, parameters)

		result = node_evaluator.eval(template['Resources']['ResourceB']['Properties']['PropertyA'])
		self.assertEqual(result, 'Param1Value')


class WhenEvaluatingTemplateWithSqsRefEval(unittest.TestCase):
	def test_returns_the_queue_url(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::Queue'
			},
			'ResourceB': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						{'Ref': 'ResourceA'}
					]
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceB']['Properties']['Queues'])

		self.assertEqual([f'https://sqs.{account_config.region}.amazonaws.com/{account_config.account_id}/ResourceA'], result)


class WhenEvaluatingTemplateWithSqsRefEvalWithInvalidQueueNameType(unittest.TestCase):
	def test_raises_an_error(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::SQS::Queue',
				'Properties': {
					'QueueName': ['Invalid']
				}
			},
			'ResourceB': {
				'Type': 'AWS::SQS::QueuePolicy',
				'Properties': {
					'Queues': [
						{'Ref': 'ResourceA'}
					]
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceB']['Properties']['Queues'])

		self.assertEqual(expected_type_error('ResourceA.Properties.QueueName', 'string', "['Invalid']"), str(cm.exception))


class WhenEvaluatingTemplateWithAnInvalidRef(unittest.TestCase):
	def test_raises_exception(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Ref': 'InvalidRef'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('Unable to find a referenced resource or parameter in template: InvalidRef', str(context.exception))


class WhenEvaluatingTemplateWithARefToAParameterThatIsNotPassedIn(unittest.TestCase):
	def test_raises_exception(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Ref': 'Param1'
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('No value passed for referenced parameter: Param1.'
						 '\nParameters are passed using the --parameters flag.', str(context.exception))


class WhenEvaluatingATemplateWithAnInvalidRef(unittest.TestCase):
	def test_raises_exception(self):
		template = load({
			'Parameters': {
				'Param1': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Ref': ['Not', 'Valid']
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Ref', 'string', "['Not', 'Valid']"), str(context.exception))
