"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import unittest

from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load_resources


class WhenEvaluatingNoValueInObject(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_removes_property_with_no_value(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Ref': 'AWS::NoValue'
					},
					'PropertyB': 'ValueB'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertNotIn('PropertyA', result['Properties'])
		self.assertIn('PropertyB', result['Properties'])

	@mock_node_evaluator_setup()
	def test_removes_nested_property_with_no_value(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'NestedProp': {
							'Ref': 'AWS::NoValue'
						},
						'OtherNestedProp': 'ValueNested'
					},
					'PropertyB': 'ValueB'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual(len(result['Properties']), 2)
		self.assertIn('PropertyA', result['Properties'])
		self.assertIn('PropertyB', result['Properties'])
		self.assertNotIn('NestedProp', result['Properties']['PropertyA'])
		self.assertIn('OtherNestedProp', result['Properties']['PropertyA'])


class WhenEvaluatingNoValueInList(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_removes_item_with_no_value(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': [
						{
							'Ref': 'AWS::NoValue'
						},
						'Item2'
					],
					'PropertyB': 'ValueB'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual(len(result['Properties']['PropertyA']), 1)
		self.assertEqual(result['Properties']['PropertyA'][0], 'Item2')


class WhenEvaluatingNoValueInListAndNoValueIsOnlyMember(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_removes_item_but_leaves_empty_list(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': [
						{
							'Ref': 'AWS::NoValue'
						}
					],
					'PropertyB': 'ValueB'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual(len(result['Properties']['PropertyA']), 0)


class WhenEvaluatingResourceWithThatDoesNotContainNoValue(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_removes_item_but_leaves_empty_list(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': 'ValueA',
					'PropertyB': 'ValueB'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual(len(result['Properties']), 2)
		self.assertEqual(result['Properties']['PropertyA'], 'ValueA')
		self.assertEqual(result['Properties']['PropertyB'], 'ValueB')
