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


s3_multi_region_access_point_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': [
                's3:PutObject',
                's3:GetObject'
            ],
            'Resource': 'arn:aws:s3:::MyTestBucket/*',
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


s3_multi_region_access_point_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 's3:*',
            'Resource': [
                {"Fn::GetAtt": ["MyBucket", "Arn"]},
                {"Fn::Sub": 'arn:aws:s3:::${MyBucket}/*'}
            ],
            'Principal': '*',
            'Condition': {
                'ArnNotEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::971691587463:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}


class WhenParsingAnS3MultiRegionAccessPointPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_name(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('MrapName', 'Resources.ResourceA.Properties'),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': ['MyMultiRegionAccessPoint'],
                    'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.MrapName', 'string', "['MyMultiRegionAccessPoint']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_policy(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': 'MyMultiRegionAccessPoint'
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Policy', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': 'MyMultiRegionAccessPoint',
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
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': 'MyMultiRegionAccessPoint',
                    'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_no_reference),
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
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': 'MyMultiRegionAccessPoint',
                    'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_no_reference),
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
                    'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                    'Properties': {
                        'MrapName': 'MyMultiRegionAccessPoint',
                        'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyMultiRegionAccessPoint", resource.ResourceName)
        self.assertEqual('AWS::S3::MultiRegionAccessPoint', resource.ResourceType)

        self.assertEqual('MultiRegionAccessPointPolicy', resource.Policy.Name)
        self.assertEqual(s3_multi_region_access_point_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3AccessPointPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in an access point
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyBucket': {
                'Type': 'AWS::S3::Bucket',
                'Properties': {
                    'BucketName': 'MyCustomBucketName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::S3::MultiRegionAccessPointPolicy',
                'Properties': {
                    'MrapName': {'Ref': 'MyBucket'},
                    'Policy': copy.deepcopy(s3_multi_region_access_point_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomBucketName", resource.ResourceName)
        self.assertEqual('AWS::S3::MultiRegionAccessPoint', resource.ResourceType)

        expected_policy = copy.deepcopy(s3_multi_region_access_point_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            'arn:aws:s3:::MyCustomBucketName',
            'arn:aws:s3:::MyCustomBucketName/*'
        ]
        self.assertEqual('MultiRegionAccessPointPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)
