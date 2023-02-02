"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests import offline_only
from cfn_policy_validator.tests.boto_mocks import BotoResponse
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, account_config, build_node_evaluator


class WhenEvaluatingTemplateWithImportValueFunction(unittest.TestCase):
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

    @mock_node_evaluator_setup(
        cloudformation=[
            BotoResponse(
                method='list_exports',
                service_response=list_exports_result
            ),
            BotoResponse(
                method='list_exports',
                service_response=list_exports_result
            )
        ]
    )
    @offline_only
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

        node_evaluator = build_node_evaluator(template, {
            'DomainParam': 'MyValue'
        })

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertEqual('Value456', result)

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])
        self.assertEqual('Value123', result)


class WhenImportingAValueThatDoesNotExist(unittest.TestCase):
    @mock_node_evaluator_setup(
        cloudformation=[
            BotoResponse(
                method='list_exports',
                service_response={
                    'Exports': []
                }
            )
        ]
    )
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

        node_evaluator = build_node_evaluator(template, {
            'DomainParam': 'MyValue'
        })

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual("Unable to resolve Fn::ImportValue. Could not find a stack export to import with value MyNonExistentOutputValue.", str(cm.exception))
