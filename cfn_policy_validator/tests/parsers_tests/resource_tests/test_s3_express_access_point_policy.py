"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError


s3_express_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 's3express:*',
            'Resource': 'arn:aws:s3express:us-east-1:123456789012:accesspoint/MyTestAccessPoint',
            'Principal': '*',
            'Condition': {
                'ArnEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::971691587463:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}


s3_express_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 's3express:*',
            'Resource': [
                {"Fn::GetAtt": ["MyAccessPoint", "Arn"]},
                {"Fn::Sub": 'arn:aws:s3express:${AWS::Region}:${AWS::AccountId}:accesspoint/${MyAccessPoint}'}
            ],
            'Principal': '*',
            'Condition': {
                'StringEquals': {
                    's3express:AccessPointNetworkOrigin': {"Fn::GetAtt": ["MyAccessPoint", "NetworkOrigin"]}
                }
            }
        }
    ]
}


class WhenParsingAnS3ExpressAccessPointPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': ['MyAccessPoint'],
                    'Policy': copy.deepcopy(s3_express_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Name', 'string', "['MyAccessPoint']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.Policy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_vpc_configuration_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': copy.deepcopy(s3_express_policy_with_no_reference),
                    'VpcConfiguration': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.VpcConfiguration', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': copy.deepcopy(s3_express_policy_with_no_reference),
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
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': copy.deepcopy(s3_express_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnS3ExpressAccessPointPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3Express::AccessPoint',
                    'Properties': {
                        'Name': 'MyAccessPoint',
                        'Policy': copy.deepcopy(s3_express_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3Express::AccessPoint', resource.ResourceType)

        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(s3_express_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3ExpressAccessPointPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in an access point
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyAccessPoint': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyCustomAccessPointName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': {'Ref': 'MyAccessPoint'},
                    'Policy': copy.deepcopy(s3_express_policy_with_reference),
                    'VpcConfiguration': {
                        'VpcId': 'vpc-0a53287fa4EXAMPLE'
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomAccessPointName", resource.ResourceName)
        self.assertEqual('AWS::S3Express::AccessPoint', resource.ResourceType)

        expected_policy = copy.deepcopy(s3_express_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:s3express:{account_config.region}:{account_config.account_id}:accesspoint/MyCustomAccessPointName',
            f'arn:aws:s3express:{account_config.region}:{account_config.account_id}:accesspoint/MyCustomAccessPointName'
        ]
        expected_policy['Statement'][0]['Condition']['StringEquals'] = {
            's3express:AccessPointNetworkOrigin': 'Internet'
        }
        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

        self.assertIsNotNone(resource.Configuration)
        self.assertEqual('vpc-0a53287fa4EXAMPLE', resource.Configuration['VpcId'])


class WhenParsingAnS3ExpressAccessPointPolicyWithAnImplicitAccessPointName(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Policy': copy.deepcopy(s3_express_policy_with_no_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("ResourceA", resource.ResourceName)
        self.assertEqual('AWS::S3Express::AccessPoint', resource.ResourceType)

        expected_policy = s3_express_policy_with_no_reference
        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3ExpressAccessPointAndThereIsNoPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_no_resources(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Express::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint'
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 0)


class WhenParsingAnS3ExpressAccessPointAndThereIsNoVpcConfiguration(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_resource_without_metadata(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3Express::AccessPoint',
                    'Properties': {
                        'Name': 'MyAccessPoint',
                        'Policy': copy.deepcopy(s3_express_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3Express::AccessPoint', resource.ResourceType)

        self.assertEqual('Policy', resource.Policy.Name)
        self.assertEqual(s3_express_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

        self.assertEqual(0, len(resource.Configuration))