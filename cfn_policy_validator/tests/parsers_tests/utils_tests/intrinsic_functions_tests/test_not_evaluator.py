"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator, expected_type_error, should_be_non_empty_error, \
    too_long_error


class WhenEvaluatingAConditionWithANotFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_evaluates_to_true(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Not': [{
                        'Fn::Equals': [
                            "abc",
                            "def"
                        ]
                    }]
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
                    'Fn::Not': [{
                        'Fn::Equals': [
                            "abc",
                            "abc"
                        ]
                    }]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertFalse(result)

    @mock_node_evaluator_setup()
    def test_value_does_not_return_boolean(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Not': ["blah"]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual("Could not evaluate Fn::Not. The evaluated value of a Not function must be a boolean. "
                         "Value does not evaluate to a boolean: ['blah']", str(cm.exception))


class WhenEvaluatingAConditionWithANotFunctionThatDoesNotMatchSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_function_is_not_a_list(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Not': "blah"
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Fn::Not", 'array', "'blah'"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_list_with_no_elements(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Not': []
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(should_be_non_empty_error("Fn::Not", "[]"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_list_with_more_than_one_elements(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::Not': [True, True]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_long_error("Fn::Not", "[True, True]"), str(cm.exception))
