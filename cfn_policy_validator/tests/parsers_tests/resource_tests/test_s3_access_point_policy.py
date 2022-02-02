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


def build_s3_access_point_policy_with_no_reference(access_point_name):
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': [
                    's3:PutObject',
                    's3:GetObject'
                ],
                'Resource': f'arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{access_point_name}/object/*',
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


def build_s3_access_point_policy_with_reference(access_point_name):
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Deny',
                'Action': 's3:*',
                'Resource': [
                    f'arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{access_point_name}',
                    f'arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{access_point_name}/object/*'
                ],
                'Principal': '*',
                'Condition': {
                    'ArnNotEquals': {
                        'aws:PrincipalArn': [
                            {'Fn::Sub': f'arn:aws:iam::{account_config.account_id}:role/${{MyTestRoleName}}'}
                        ]
                    }
                }
            }
        ]
    }


class WhenParsingAnS3AccessPointPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'Name': ['MyAccessPoint'],
                    'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                    'VpcConfiguration': {}
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('ResourceA.Properties.Name', 'string', "['MyAccessPoint']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'Name': 'MyAccessPoint',
                    'Policy': ['Invalid'],
                    'VpcConfiguration': {}
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('ResourceA.Properties.Policy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_vpc_configuration_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'Name': 'MyAccessPoint',
                    'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                    'VpcConfiguration': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('ResourceA.Properties.VpcConfiguration', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                    'Bucket': 'MyBucket',
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
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Name': 'MyAccessPoint',
                    'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                    'Bucket': 'MyBucket',
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnS3AccessPointPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3::AccessPoint',
                    'Properties': {
                        'Name': 'MyAccessPoint',
                        'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                        'Bucket': 'MyBucket',
                        'VpcConfiguration': {
                            'VpcId': 'vpc-0a53287fa4EXAMPLE'
                        }
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3::AccessPoint', resource.ResourceType)

        self.assertEqual('AccessPointPolicy', resource.Policy.Name)
        self.assertEqual(build_s3_access_point_policy_with_no_reference('MyAccessPoint'), resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

        self.assertIsNotNone(resource.Configuration)
        self.assertEqual('vpc-0a53287fa4EXAMPLE', resource.Configuration['VpcId'])


class WhenParsingAnS3AccessPointPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in an access point
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load({
            'Parameters': {
                'AccessPointName': {},
                'MyTestRoleName': {},
                'MyVpc': {}
            },
            'Resources': {
                'MyBucket': {
                    'Type': 'AWS::S3::Bucket',
                    'Properties': {
                        'BucketName': 'MyCustomBucketName'
                    }
                },
                'ResourceA': {
                    'Type': 'AWS::S3::AccessPoint',
                    'Properties': {
                        'Name': {'Ref': 'AccessPointName'},
                        'Policy': build_s3_access_point_policy_with_reference('MyAccessPoint'),
                        'Bucket': {'Ref': 'MyBucket'},
                        'VpcConfiguration': {
                            'VpcId': {
                                'Ref': 'MyVpc'
                            }
                        }
                    }
                }
            }
        }, parameters={
            'AccessPointName': 'MyAccessPoint',
            'MyTestRoleName': 'MyTestRole',
            'MyVpc': 'vpc-0a53287fa4EXAMPLE'
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3::AccessPoint', resource.ResourceType)

        expected_policy = build_s3_access_point_policy_with_reference('MyAccessPoint')
        expected_policy['Statement'][0]['Condition']['ArnNotEquals']['aws:PrincipalArn'] = [
            f'arn:aws:iam::{account_config.account_id}:role/MyTestRole'
        ]
        self.assertEqual('AccessPointPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

        self.assertIsNotNone(resource.Configuration)
        self.assertEqual('vpc-0a53287fa4EXAMPLE', resource.Configuration['VpcId'])


class WhenParsingAnS3AccessPointPolicyWithAnImplicitAccessPointName(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'Policy': build_s3_access_point_policy_with_no_reference('ResourceA')
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("ResourceA", resource.ResourceName)
        self.assertEqual('AWS::S3::AccessPoint', resource.ResourceType)

        expected_policy = build_s3_access_point_policy_with_no_reference('ResourceA')
        self.assertEqual('AccessPointPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3AccessPointAndThereIsNoPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_no_resources(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::AccessPoint',
                'Properties': {
                    'Bucket': 'MyBucket'
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 0)


class WhenParsingAnS3AccessPointAndThereIsNoVpcConfiguration(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_resource_without_metadata(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3::AccessPoint',
                    'Properties': {
                        'Name': 'MyAccessPoint',
                        'Policy': build_s3_access_point_policy_with_no_reference('MyAccessPoint'),
                        'Bucket': 'MyBucket'
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3::AccessPoint', resource.ResourceType)

        self.assertEqual('AccessPointPolicy', resource.Policy.Name)
        self.assertEqual(build_s3_access_point_policy_with_no_reference('MyAccessPoint'), resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

        self.assertEqual(0, len(resource.Configuration))
