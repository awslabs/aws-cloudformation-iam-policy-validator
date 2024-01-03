"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator, expected_type_error, too_short_error, \
    too_long_error


class WhenEvaluatingAConditionWithAnEqualsFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_values_are_equal(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        "abc",
                        "abc"
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_values_are_not_equal(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        "abc",
                        "def"
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertFalse(result)

    @mock_node_evaluator_setup()
    def test_first_value_is_not_string(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        111,
                        "111"
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_second_value_is_not_string(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        "111",
                        111
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_first_value_can_contain_functions(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        {
                            "Fn::Equals": [
                                "111",
                                "111"
                            ]
                        },
                        True
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_second_value_can_contain_functions(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': [
                        True,
                        {
                            "Fn::Equals": [
                                "111",
                                "111"
                            ]
                        }
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)


class WhenEvaluatingAConditionWithAnEqualsFunctionThatDoesNotMatchSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_function_is_not_a_list(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': {'NotA': 'List'}
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Fn::Equals", 'array', "{'NotA': 'List'}"),
            str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_one_element(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': ['NotA']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_short_error("Fn::Equals", "['NotA']"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_more_than_two_elements(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Equals': ['NotA', 'NotB', 'NotC']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_long_error("Fn::Equals", "['NotA', 'NotB', 'NotC']"), str(cm.exception))
