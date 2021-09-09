"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from botocore.stub import Stubber

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.utils import load, account_config


class WhenEvaluatingTemplateWithImportValueFunction(unittest.TestCase):
    def test_substitutes_imported_values(self):
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
                            'Fn::ImportValue': {
                                'Fn::Sub': ['www.${Domain}', {'Domain': {'Ref': 'DomainParam'}}]
                            }
                        },
                        'PropertyB': {
                            'Fn::ImportValue': 'MyOutputValue'
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {
            'DomainParam': 'MyValue'
        })

        list_exports_result = {
            'Exports': [
                {
                    'ExportingStackId': 'abc123',
                    'Name': 'MyOutputValue',
                    'Value': 'Value123'
                },
                {
                    'ExportingStackId': 'def123',
                    'Name': 'www.MyValue',
                    'Value': 'Value456'
                }
            ]
        }

        with Stubber(node_evaluator.evaluators['Fn::ImportValue'].cloudformation_client) as stubber:
            stubber.add_response('list_exports', list_exports_result, None)
            result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
            self.assertEqual('Value456', result)

        with Stubber(node_evaluator.evaluators['Fn::ImportValue'].cloudformation_client) as stubber:
            stubber.add_response('list_exports', list_exports_result, None)
            result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])
            self.assertEqual('Value123', result)


class WhenImportingAValueThatDoesNotExist(unittest.TestCase):
    def test_raises_exception(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::ImportValue': 'MyNonExistentOutputValue'
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {
            'DomainParam': 'MyValue'
        })

        list_exports_result = {
            'Exports': []
        }

        with Stubber(node_evaluator.evaluators['Fn::ImportValue'].cloudformation_client) as stubber:
            stubber.add_response('list_exports', list_exports_result, None)

            with self.assertRaises(ApplicationError) as cm:
                node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

            self.assertEqual("Unable to resolve Fn::ImportValue. Could not find a stack export to import with value MyNonExistentOutputValue.", str(cm.exception))
