"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator, expected_type_error, too_short_error, \
    too_long_error


class WhenEvaluatingAConditionWithAnOrFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_evaluates_to_true(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [
                        True,
                        False,
                        False,
                        False
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertTrue(result)

    @mock_node_evaluator_setup()
    def test_evaluates_to_false(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [
                        False,
                        False,
                        False,
                        False
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertFalse(result)

    @mock_node_evaluator_setup()
    def test_value_is_not_boolean(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [
                        True,
                        False,
                        True,
                        "True"
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual("Could not evaluate Fn::Or. All values of an OR function must be booleans. Value at index 3 "
                         "does not evaluate to a boolean: [True, False, True, 'True']", str(cm.exception))

    @mock_node_evaluator_setup()
    def test_value_can_contain_functions(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [
                        {
                            "Fn::Equals": [
                                "222",
                                "111"
                            ]
                        },
                        False,
                        {
                            "Fn::Equals": [
                                "abc",
                                "def"
                            ]
                        }
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertFalse(result)


class WhenEvaluatingAConditionWithAnOrFunctionThatDoesNotMatchSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_function_is_not_a_list(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': {'NotA': 'List'}
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Fn::Or", 'array', "{'NotA': 'List'}"),
            str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_one_element(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [True]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_short_error("Fn::Or", "[True]"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_more_than_ten_elements(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Or': [True, True, True, True, True, True, True, True, True, True, True]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_long_error("Fn::Or", "[True, True, True, True, True, True, True, True, True, True, True]"), str(cm.exception))
