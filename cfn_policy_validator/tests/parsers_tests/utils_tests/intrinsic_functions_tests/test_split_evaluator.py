"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.utils import load, account_config, load_resources, expected_type_error


class WhenEvaluatingATemplateWithASplitFunctionThatHasAReference(unittest.TestCase):
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

        node_evaluator = NodeEvaluator(template, account_config, {
            'DomainParam': 'a.b.c'
        })

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(['a', 'b', 'c'], result)


class WhenEvaluatingATemplateWithASplitFunction(unittest.TestCase):
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

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(['a', 'b', 'c'], result)


class WhenEvaluatingTemplateWithASplitFunctionWithNoList(unittest.TestCase):
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

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error('Fn::Split', 'array', "'abc'"), str(cm.exception))


class WhenEvaluatingTemplateWithASplitFunctionWithInvalidLength(unittest.TestCase):
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

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual("Additional items are not allowed ('3rd' was unexpected), Path: Fn::Split", str(cm.exception))
