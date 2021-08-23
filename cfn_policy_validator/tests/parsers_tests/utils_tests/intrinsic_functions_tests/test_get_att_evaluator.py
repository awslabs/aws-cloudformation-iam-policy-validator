"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests import my_canonical_user_id
from cfn_policy_validator.tests.utils import load, account_config, expected_type_error, load_resources


class WhenEvaluatingAPolicyWithAGetAttToAResourceThatDoesNotExist(unittest.TestCase):
    def test_raises_exception(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::GetAtt': ['ResourceB', 'Arn']
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as context:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertTrue('Unable to find referenced resource for GetAtt reference to ResourceB.Arn' in str(context.exception), str(context.exception))


class WhenEvaluatingAPolicyWithANestedGetAtt(unittest.TestCase):
    def test_returns_the_nested_value(self):
        template = load({
            'Parameters': {
                'Param1': {
                    'Type': 'string'
                }
            },
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'Param1'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'PropertyA']
                        }
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)

        result = node_evaluator.eval(template['Resources']['ResourceB']['Properties']['PropertyA'])
        self.assertEqual(result, 'Param1Value')


class WhenEvaluatingAPolicyWithAGetAttForAnArn(unittest.TestCase):
    def test_returns_arn(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::GetAtt': ['ResourceB', 'Arn']
                    }
                }
            },
            'ResourceB': {
                'Type': 'AWS::Lambda::Function'
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:ResourceB', result)


class WhenEvaluatingAPolicyWithAGetAttForAResourceProperty(unittest.TestCase):
    def test_returns_property_value(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::GetAtt': ['ResourceB', 'Name']
                    }
                }
            },
            'ResourceB': {
                'Type': 'AWS::Lambda::Function',
                'Properties': {
                    'Name': 'ExpectedResult'
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(result, 'ExpectedResult')


class WhenEvaluatingAPolicyWithAGetAttForCloudFrontOriginAccessIdentityS3CanonicalUserId(unittest.TestCase):
    def test_returns_property_value(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        'Fn::GetAtt': ['ResourceB', 'S3CanonicalUserId']
                    }
                }
            },
            'ResourceB': {
                'Type': 'AWS::CloudFront::CloudFrontOriginAccessIdentity',
                'Properties': {
                    'Name': 'ExpectedResult'
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual(my_canonical_user_id, result)


class WhenEvaluatingAPolicyWithAGetAttForAnInvalidResourceProperty(unittest.TestCase):
    def test_raises_exception(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceB', 'Name']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Lambda::Function'
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        with self.assertRaises(ApplicationError) as context:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual('Call to GetAtt not supported for: ResourceB.Name', str(context.exception))


class WhenEvaluatingTemplateWithStringGetAttValue(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'Path': {'Ref': 'ResourceA'},
                        'RoleName': {'Fn::GetAtt': 'ResourceA'}
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['RoleName'])

        self.assertEqual(expected_type_error('Fn::GetAtt', 'array', "'ResourceA'"), str(cm.exception))


class WhenEvaluatingTemplateWithArrayGetAttValueOfInvalidLength(unittest.TestCase):
    def test_raises_an_error(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'Path': {'Ref': 'ResourceA'},
                    'RoleName': {'Fn::GetAtt': ['Property', 'Value1', 'Value2']}
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['RoleName'])

        self.assertEqual("Additional items are not allowed ('Value2' was unexpected), Path: Fn::GetAtt", str(cm.exception))
