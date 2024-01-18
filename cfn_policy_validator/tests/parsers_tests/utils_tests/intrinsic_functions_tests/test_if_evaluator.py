"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, build_node_evaluator, expected_type_error, too_short_error, \
    too_long_error


class WhenEvaluatingAConditionWithAnIfFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_comparison_is_true(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::If": [
                        "otherCondition",
                        "a",
                        "b"
                    ]
                },
                'otherCondition': {
                    'Fn::Equals': ['a', 'a']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertEqual(result, 'a')

    @mock_node_evaluator_setup()
    def test_comparison_is_false(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::If": [
                        "otherCondition",
                        "a",
                        "b"
                    ]
                },
                'otherCondition': {
                    'Fn::Not': [
                        {'Fn::Equals': ['a', 'a']}
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertEqual(result, 'b')

    @mock_node_evaluator_setup()
    def test_condition_with_name_does_not_exist(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::If": [
                        "otherCondition",
                        "a",
                        "b"
                    ]
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual('Unable to find referenced condition in template: otherCondition', str(cm.exception))

    @mock_node_evaluator_setup()
    def test_comparison_is_true_and_result_is_function(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::If": [
                        "otherCondition",
                        {'Fn::Equals': ['a', 'a']},
                        "b"
                    ]
                },
                'otherCondition': {
                    'Fn::Equals': ['a', 'a']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertEqual(result, True)

    @mock_node_evaluator_setup()
    def test_comparison_is_false_and_result_is_function(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::If": [
                        "otherCondition",
                        'a',
                        {'Fn::Equals': ['a', 'a']}
                    ]
                },
                'otherCondition': {
                    'Fn::Equals': ['a', 'b']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Conditions']['myCondition'])
        self.assertEqual(result, True)


class WhenEvaluatingAResourceWithAnIfFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_comparison_is_true(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::Equals": ['a', 'a']
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::If': [
                                'myCondition',
                                'a',
                                'b'
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, 'a')

    @mock_node_evaluator_setup()
    def test_comparison_is_false(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::Equals": ['a', 'b']
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::If': [
                                'myCondition',
                                'a',
                                'b'
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, 'b')

    @mock_node_evaluator_setup()
    def test_condition_with_name_does_not_exist(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::If': [
                                'myCondition',
                                'a',
                                'b'
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual('Unable to find referenced condition in template: myCondition', str(cm.exception))

    @mock_node_evaluator_setup()
    def test_comparison_is_true_and_result_is_function(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::Equals": ['a', 'a']
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::If': [
                                'myCondition',
                                {'Fn::Equals': ['a', 'a']},
                                'b'
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, True)

    @mock_node_evaluator_setup()
    def test_comparison_is_false_and_result_is_function(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    "Fn::Equals": ['a', 'b']
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::If': [
                                'myCondition',
                                'a',
                                {'Fn::Equals': ['a', 'a']}
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, True)


class WhenEvaluatingAConditionWithAnIfFunctionThatDoesNotMatchSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_condition_value_is_not_list(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::If': {'NotA': 'List'}
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Fn::If", 'array', "{'NotA': 'List'}"),
            str(cm.exception))

    @mock_node_evaluator_setup()
    def test_condition_name_is_not_string(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::If': [{'NotA': 'String'}, 'a', 'b']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(expected_type_error("Fn::If.0", 'string', "{'NotA': 'String'}"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_more_than_three_items(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::If': ['myOtherCondition', 'a', 'b', 'c']
                },
                'myOtherCondition': {
                    'Fn::Equals': ['a', 'a']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_long_error("Fn::If", "['myOtherCondition', 'a', 'b', 'c']"), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_function_has_less_than_three_items(self):
        template = load({
            'Conditions': {
                'myCondition': {
                    'Fn::If': ['myOtherCondition', 'a']
                },
                'myOtherCondition': {
                    'Fn::Equals': ['a', 'a']
                }
            },
            'Resources': {}
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Conditions']['myCondition'])

        self.assertEqual(too_short_error("Fn::If", "['myOtherCondition', 'a']"), str(cm.exception))
