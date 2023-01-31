"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, load_resources, account_config, expected_type_error, default_get_latest_ssm_parameter_version


class WhenEvaluatingAPolicyWithASelectFunction(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_value_at_index_1(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Select': ['1', ['option 0', 'option 1']]
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'option 1')


class WhenEvaluatingAPolicyWithASelectFunctionThatReturnsAnObject(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_value_at_index_0(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Select': ['0', [{'option': '0'}, {'option': '1'}]]
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, {'option': '0'})


class WhenEvaluatingAPolicyWithASelectFunctionAndInvalidValue(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Select': '0'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::Select', 'array', "'0'"), str(context.exception))


class WhenEvaluatingAPolicyWithASelectFunctionAndAListNotEqualToTwo(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Select': ['0', ['option 0'], '3rd']
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual("Additional items are not allowed ('3rd' was unexpected), Path: Fn::Select", str(context.exception))


class WhenEvaluatingAPolicyWithASelectFunctionAndAnInvalidFirstValue(unittest.TestCase):
	@mock_node_evaluator_setup()
	def tests_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Select': ['a', ['option 0', 'option 1']]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual("The first value for Fn::Select must be an integer. Invalid value: a", str(context.exception))


class WhenEvaluatingAPolicyWithASelectFunctionAndAnInvalidSecondValue(unittest.TestCase):
	@mock_node_evaluator_setup()
	def tests_raises_an_error(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Select': ['1', 'option 0']
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::Select.1', 'array', "'option 0'"), str(context.exception))


class WhenEvaluatingAPolicyWithASelectFunctionAndIndexIsLargerThanList(unittest.TestCase):
	@mock_node_evaluator_setup()
	def tests_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Select': ['2', ['option 0', 'option 1']]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual("Fn::Select index is out of bounds of the list.  Invalid value: ['2', ['option 0', 'option 1']]", str(context.exception))


class WhenEvaluatingAPolicyWithASelectFunctionAndIndexIsNegative(unittest.TestCase):
	@mock_node_evaluator_setup()
	def tests_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Select': ['-1', ['option 0', 'option 1']]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual("Fn::Select index is out of bounds of the list.  Invalid value: ['-1', ['option 0', 'option 1']]", str(context.exception))
