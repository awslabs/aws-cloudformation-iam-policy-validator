"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.parsers_tests.test_identity import assume_role_policy_doc
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

    @mock_node_evaluator_setup()
    def test_condition_in_resources_section_is_not_evaluated(self):
        template = load({
            'Conditions': {},
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'Path': '/custom/path',
                        'RoleName': 'MyRole',
                        'AssumeRolePolicyDocument': copy.deepcopy(assume_role_policy_doc),
                        'Policies': [{
                            'PolicyDocument': {
                                'Version': '2012-10-17',
                                'Statement': [
                                    {
                                        # not a valid statement, but we want to make sure this is not parsed as a
                                        # CFN condition
                                        'Condition': {
                                            "StringEquals": {
                                                "aws:PrincipalAccount": "111111111111"
                                            }
                                        }
                                    }
                                ]
                            }
                        }]
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA'])
        self.assertEqual(result['Properties']['Policies'][0]['PolicyDocument']['Statement'][0]['Condition']['StringEquals']['aws:PrincipalAccount'], '111111111111')


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
