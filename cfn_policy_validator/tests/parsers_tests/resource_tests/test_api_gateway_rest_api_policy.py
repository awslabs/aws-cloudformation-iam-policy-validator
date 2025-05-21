"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator import client
from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests.boto_mocks import BotoResponse, get_test_mode


api_gateway_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'execute-api:Invoke',
            'Resource': 'arn:aws:execute-api:us-east-1:123456789012:api123/*/GET/',
            'Principal': '*',
            'Condition': {
                'IpAddress': {
                    'aws:SourceIp': '192.0.2.0/24'
                }
            }
        }
    ]
}


api_gateway_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 'execute-api:Invoke',
            'Sid': {"Fn::Join": ["", ["Policy-for-", {"Fn::GetAtt": ["MyRestApi", "RestApiId"]}, "-", {"Fn::GetAtt": ["MyRestApi", "RootResourceId"]}]]},
            'Resource': [
                {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${MyRestApi}/*/*/*"},
                {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${MyRestApi}/*/GET/"}
            ],
            'Principal': '*',
            'Condition': {
                'NotIpAddress': {
                    'aws:SourceIp': [
                        "192.0.2.0/24",
                        "198.51.100.0/24"
                    ]
                }
            }
        }
    ]
}


class WhenParsingAnApiGatewayRestApiPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_name(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::ApiGateway::RestApi',
                    'Properties': {
                        'Policy': copy.deepcopy(api_gateway_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Name', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': ['MyRestApi'],
                    'Policy': copy.deepcopy(api_gateway_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Name', 'string', "['MyRestApi']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': 'MyRestApi',
                    'Policy': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Policy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': 'MyRestApi',
                    'Policy': copy.deepcopy(api_gateway_policy_with_no_reference),
                    'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')

    @mock_node_evaluator_setup()
    def test_with_ref_to_parameter_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': 'MyRestApi',
                    'Policy': copy.deepcopy(api_gateway_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnApiGatewayRestApiPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::ApiGateway::RestApi',
                    'Properties': {
                        'Name': 'MyRestApi',
                        'Policy': copy.deepcopy(api_gateway_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyRestApi", resource.ResourceName)
        self.assertEqual('AWS::ApiGateway::RestApi', resource.ResourceType)

        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(api_gateway_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnApiGatewayRestApiPolicyWithReferencesInEachField(unittest.TestCase):
    rest_api_id = "a1bcdef2gh"
    root_resource_id="qqfd3vd4gd"

    def setUp(self):
        if get_test_mode() == "OFFLINE":
            return
        # Create a real API Gateway for testing
        self.apigateway_client = client.build('apigateway', account_config.region)
        
        # Create a test API
        response = self.apigateway_client.create_rest_api(
            name='MyCustomRestApi',
            description='Test API for policy validator'
        )
        self.rest_api_id = response['id']
        self.root_resource_id = response['rootResourceId']
        
    def tearDown(self):
        if get_test_mode() == "OFFLINE":
            return
        # Clean up the test API
        if hasattr(self, 'rest_api_id'):
            self.apigateway_client.delete_rest_api(
                restApiId=self.rest_api_id
            )
    

    # this is a test to ensure that each field is being evaluated for references in a rest api
    @mock_node_evaluator_setup(
        apigateway=[
            BotoResponse(
                method='get_rest_apis',
                service_response= {
                    'items': [
                        {
                            'id': rest_api_id,
                            'name': 'MyCustomRestApi',
                            'rootResourceId': root_resource_id
                        }
                    ]
                },
                expected_params=None
            )
        ]
    )
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyRestApi': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': 'MyCustomRestApi'
                }
            },
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': {"Ref": "MyRestApi"},
                    'Policy': copy.deepcopy(api_gateway_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual(self.rest_api_id, resource.ResourceName)
        self.assertEqual('AWS::ApiGateway::RestApi', resource.ResourceType)

        expected_policy = copy.deepcopy(api_gateway_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:execute-api:{account_config.region}:{account_config.account_id}:{self.rest_api_id}/*/*/*',
            f'arn:aws:execute-api:{account_config.region}:{account_config.account_id}:{self.rest_api_id}/*/GET/'
        ]
        expected_policy['Statement'][0]['Sid'] = f'Policy-for-{self.rest_api_id}-{self.root_resource_id}'
        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnApiGatewayRestApiWithNoPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_no_resources(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::ApiGateway::RestApi',
                'Properties': {
                    'Name': 'MyRestApi'
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 0)