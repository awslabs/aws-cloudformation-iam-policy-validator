"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.utils import load, account_config, expected_type_error, load_resources


class WhenEvaluatingAPolicyWithAJoinFunction(unittest.TestCase):
    def test_returns_a_single_string(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Join': [
                                "", [
                                  "arn:",
                                  {
                                    "Ref": "AWS::Partition"
                                  },
                                  ":s3:::elasticbeanstalk-*-",
                                  {
                                    "Ref": "AWS::AccountId"
                                  }
                                ]
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, f'arn:aws:s3:::elasticbeanstalk-*-{account_config.account_id}')


class WhenEvaluatingAPolicyWithAJoinFunctionThatIsNotAList(unittest.TestCase):
    def test_raises_an_exception(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Join': {
                            "": [
                              "arn:",
                              {
                                "Ref": "AWS::Partition"
                              },
                              ":s3:::elasticbeanstalk-*-",
                              {
                                "Ref": "AWS::AccountId"
                              }
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error("Fn::Join", 'array',
                                             "{'': ['arn:', {'Ref': 'AWS::Partition'}, ':s3:::elasticbeanstalk-*-', {'Ref': 'AWS::AccountId'}]}"), str(cm.exception))


class WhenEvaluatingAPolicyWithAJoinFunctionThatIsAListThatDoesNotHaveTwoValues(unittest.TestCase):
    def test_raises_an_exception(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Join': [
                            "", [
                              "arn:",
                              {
                                "Ref": "AWS::Partition"
                              },
                              ":s3:::elasticbeanstalk-*-",
                              {
                                "Ref": "AWS::AccountId"
                              }
                            ],
                            "3rd val"
                        ]
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as context:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual("Additional items are not allowed ('3rd val' was unexpected), Path: Fn::Join", str(context.exception))


class WhenEvaluatingAPolicyWithAJoinFunctionWithNonStringDelimiter(unittest.TestCase):
    def test_raises_an_exception(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Join': [
                            {}, [
                              "arn:",
                              {
                                "Ref": "AWS::Partition"
                              },
                              ":s3:::elasticbeanstalk-*-",
                              {
                                "Ref": "AWS::AccountId"
                              }
                            ]
                        ]
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as context:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error('Fn::Join.0', 'string', '{}'), str(context.exception))


class WhenEvaluatingAPolicyWithAJoinFunctionWithNonListValue(unittest.TestCase):
    def test_raises_an_exception(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Join': [
                                "", "string"
                            ]
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as context:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error("Fn::Join.1", "array", "'string'"), str(context.exception))


class WhenEvaluatingTemplateWithAJoinFunctionWithValuesThatAreNotStrings(unittest.TestCase):
    def test_returns_a_single_string(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::Join': [
                            "", [
                              ["arn:"],
                              {
                                "Ref": "AWS::Partition"
                              },
                              ":s3:::elasticbeanstalk-*-",
                              {
                                "Ref": "AWS::AccountId"
                              }
                            ]
                        ]
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual(expected_type_error('Fn::Join.1.0', 'string', "['arn:']"), str(cm.exception))

