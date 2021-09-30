"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError


s3_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 's3:*',
            'Resource': 'arn:aws:s3:::MyTestBucket',
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


s3_policy_with_reference = {
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


class WhenParsingAnS3BucketPolicyAndValidatingSchema(unittest.TestCase):
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

    def test_with_no_bucket(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3::BucketPolicy',
                    'Properties': {
                        'PolicyDocument': copy.deepcopy(s3_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Bucket', 'ResourceA.Properties'), str(cm.exception))

    def test_with_invalid_bucket_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': ['MyBucket'],
                    'PolicyDocument': copy.deepcopy(s3_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('ResourceA.Properties.Bucket', 'string', "['MyBucket']"),  str(cm.exception))

    def test_with_no_policy_document(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': 'MyBucket'
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('PolicyDocument', 'ResourceA.Properties'), str(cm.exception))

    def test_with_invalid_policy_document_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'PolicyDocument': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('ResourceA.Properties.PolicyDocument', 'object', "['Invalid']"),
                         str(cm.exception))

    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'PolicyDocument': copy.deepcopy(s3_policy_with_no_reference),
                    'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')

    def test_with_ref_to_parameter_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': 'MyBucket',
                    'PolicyDocument': copy.deepcopy(s3_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnS3BucketPolicy(unittest.TestCase):
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'TestBucket': {
                    'Type': 'AWS::S3::Bucket'
                },
                'ResourceA': {
                    'Type': 'AWS::S3::BucketPolicy',
                    'Properties': {
                        'Bucket': 'MyBucket',
                        'PolicyDocument': copy.deepcopy(s3_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyBucket", resource.ResourceName)
        self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

        self.assertEqual('BucketPolicy', resource.Policy.Name)
        self.assertEqual(s3_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3BucketPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a role
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyBucket': {
                'Type': 'AWS::S3::Bucket',
                'Properties': {
                    'BucketName': 'MyCustomBucketName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': {'Ref': 'MyBucket'},
                    'PolicyDocument': copy.deepcopy(s3_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomBucketName", resource.ResourceName)
        self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

        expected_policy = copy.deepcopy(s3_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            'arn:aws:s3:::MyCustomBucketName',
            'arn:aws:s3:::MyCustomBucketName/*'
        ]
        self.assertEqual('BucketPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3BucketPolicyWithAnExplicitBucketName(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a role
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyBucket': {
                'Type': 'AWS::S3::Bucket',
                'Properties': {
                    'BucketName': 'MyCustomBucketName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::S3::BucketPolicy',
                'Properties': {
                    'Bucket': {'Ref': 'MyBucket'},
                    'PolicyDocument': copy.deepcopy(s3_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomBucketName", resource.ResourceName)
        self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

        expected_policy = copy.deepcopy(s3_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            'arn:aws:s3:::MyCustomBucketName',
            'arn:aws:s3:::MyCustomBucketName/*'
        ]
        self.assertEqual('BucketPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


