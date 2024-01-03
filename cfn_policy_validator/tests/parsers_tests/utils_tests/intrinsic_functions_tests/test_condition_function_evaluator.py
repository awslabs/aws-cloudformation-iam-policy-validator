"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator, expected_type_error


class WhenEvaluatingAConditionWithAConditionFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_gets_value_from_other_condition(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        {'Condition': 'myOtherCondition'},
                        True
                    ]
                },
                'myOtherCondition': {
                    'Fn::Equals': ['abc', 'abc']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_condition_with_name_does_not_exist(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        {'Condition': 'myOtherCondition'},
                        True
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual('Unable to find referenced condition in template: myOtherCondition', str(cm.exception))


class WhenEvaluatingAConditionWithAConditionFunctionThatDoesNotMatchSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_function_is_not_a_string(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Condition': True
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Condition", 'string', "True"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_is_an_intrinsic_function(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Condition': {'Fn::Equals': [True, True]}
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Condition", 'string', "{'Fn::Equals': [True, True]}"), str(cm.exception))
