"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, load_resources, expected_type_error, \
    build_node_evaluator


class WhenEvaluatingATemplateWithASplitFunctionThatHasAReference(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_splits_into_list(self):
        template = load({
            'Parameters': {
                'DomainParam': {
                    'Type': 'string'
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Split': [".", {"Ref": "DomainParam"}]
                        }
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template, {
            'DomainParam': 'a.b.c'
        })

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(['a', 'b', 'c'], result)


class WhenEvaluatingATemplateWithASplitFunction(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_splits_into_list(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Split': [",", "a,b,c"]
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(['a', 'b', 'c'], result)


class WhenEvaluatingTemplateWithASplitFunctionWithNoList(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_raises_an_error(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Split': "abc"
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error('Fn::Split', 'array', "'abc'"), str(cm.exception))


class WhenEvaluatingTemplateWithASplitFunctionWithInvalidLength(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_raises_an_error(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Split': [',', 'a,b,c', '3rd']
                    }
                }
            }
        })

        node_evaluator = build_node_evaluator(template)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual("Additional items are not allowed ('3rd' was unexpected), Path: Fn::Split", str(cm.exception))
