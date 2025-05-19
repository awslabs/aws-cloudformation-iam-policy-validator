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


table_bucket_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 's3:*',
            'Resource': 'arn:aws:s3tables:::bucket/MyTestTableBucket',
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


table_bucket_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 's3:*',
            'Sid': {"Fn::Join": ["", ["Policy-For-", {"Ref": "MyTableBucket"}]]},
            'Resource': [
                {"Fn::GetAtt": ["MyTableBucket", "TableBucketARN"]},
                {"Fn::Sub": 'arn:aws:s3tables:::bucket/${MyTableBucket}/*'}
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


class WhenParsingAnS3TablesTableBucketPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_table_bucket_arn(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3Tables::TableBucketPolicy',
                    'Properties': {
                        'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('TableBucketARN', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_table_bucket_arn_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': ['arn:aws:s3tables:::bucket/MyTableBucket'],
                    'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.TableBucketARN', 'string', "['arn:aws:s3tables:::bucket/MyTableBucket']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_resource_policy(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': 'arn:aws:s3tables:::bucket/MyTableBucket'
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('ResourcePolicy', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_resource_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': 'arn:aws:s3tables:::bucket/MyTableBucket',
                    'ResourcePolicy': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ResourcePolicy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': 'arn:aws:s3tables:::bucket/MyTableBucket',
                    'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference),
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
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': 'arn:aws:s3tables:::bucket/MyTableBucket',
                    'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnS3TablesTableBucketPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'TestTableBucket': {
                    'Type': 'AWS::S3Tables::TableBucket',
                    'Properties': {
                        'TableBucketName': 'MyTableBucket'
                    }
                },
                'ResourceA': {
                    'Type': 'AWS::S3Tables::TableBucketPolicy',
                    'Properties': {
                        'TableBucketARN': 'arn:aws:s3tables:::bucket/MyTableBucket',
                        'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyTableBucket", resource.ResourceName)
        self.assertEqual('AWS::S3Tables::TableBucket', resource.ResourceType)

        self.assertEqual('TableBucketPolicy', resource.Policy.Name)
        self.assertEqual(table_bucket_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3TablesTableBucketPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a table bucket
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyTableBucket': {
                'Type': 'AWS::S3Tables::TableBucket',
                'Properties': {
                    'TableBucketName': 'MyCustomTableBucketName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::S3Tables::TableBucketPolicy',
                'Properties': {
                    'TableBucketARN': {'Fn::GetAtt': ['MyTableBucket', 'TableBucketARN']},
                    'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomTableBucketName", resource.ResourceName)
        self.assertEqual('AWS::S3Tables::TableBucket', resource.ResourceType)

        expected_policy = copy.deepcopy(table_bucket_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:s3tables:{account_config.region}:{account_config.account_id}:bucket/MyCustomTableBucketName',
            f'arn:aws:s3tables:::bucket/MyCustomTableBucketName/*'
        ]
        expected_policy['Statement'][0]['Sid'] = f'Policy-For-MyCustomTableBucketName'
        self.assertEqual('TableBucketPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingAnS3TablesTableBucketPolicyWithInvalidARN(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_raises_error_for_invalid_arn(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3Tables::TableBucketPolicy',
                    'Properties': {
                        'TableBucketARN': 'arn:aws:s3tables:::invalid-arn',
                        'ResourcePolicy': copy.deepcopy(table_bucket_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual("Invalid value for Resources.ResourceA.Properties.TableBucketARN. Must be a valid TableBucket ARN. TableBucketARN value: arn:aws:s3tables:::invalid-arn", str(cm.exception))