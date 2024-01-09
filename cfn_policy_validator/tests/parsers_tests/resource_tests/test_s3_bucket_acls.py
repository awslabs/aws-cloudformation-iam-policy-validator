"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import load, account_config, expected_type_error, \
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

class WhenParsingAnS3BucketAndValidatingSchema(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_with_invalid_bucket_name_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'BucketName': ['MyBucket']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.BucketName', 'string', "['MyBucket']"),  str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_invalid_access_control_type(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'AccessControl': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties.AccessControl', 'string', "['Invalid']"),
						 str(cm.exception))

	@mock_node_evaluator_setup()
	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
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
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingAnS3BucketAclWithNoProperties(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_no_resource(self):
		template = load({
			'Resources': {
				'TestBucket': {
					'Type': 'AWS::S3::Bucket'
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 0)


class WhenParsingAnS3BucketAclWithNoAccessControl(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_no_resource_with_just_properties(self):
		template = load({
			'Resources': {
				'TestBucket': {
					'Type': 'AWS::S3::Bucket',
					'Properties': {}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 0)

	@mock_node_evaluator_setup()
	def test_returns_no_resource_with_bucket_name(self):
		template = load({
			'Resources': {
				'TestBucket': {
					'Type': 'AWS::S3::Bucket',
					'Properties': {
						'BucketName': 'MyBucket'
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 0)


class WhenParsingAnS3BucketAclWithNoBucketName(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource(self):
		template = load({
			'Resources': {
				'TestBucket': {
					'Type': 'AWS::S3::Bucket',
					'Properties': {
						'AccessControl': 'BucketOwnerFullControl'
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("TestBucket", resource.ResourceName)
		self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

		self.assertEqual("BucketAcl", resource.Policy.Name)
		self.assertIsNone(resource.Policy.Policy)
		self.assertEqual("BucketOwnerFullControl", resource.Configuration["AccessControl"])


class WhenParsingAnS3BucketAclWithExplicitBucketName(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource(self):
		template = load({
			'Resources': {
				'TestBucket': {
					'Type': 'AWS::S3::Bucket',
					'Properties': {
						'BucketName': 'MyBucket',
						'AccessControl': 'BucketOwnerFullControl'
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyBucket", resource.ResourceName)
		self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

		self.assertEqual("BucketAcl", resource.Policy.Name)
		self.assertIsNone(resource.Policy.Policy)
		self.assertEqual("BucketOwnerFullControl", resource.Configuration["AccessControl"])


class WhenParsingAnS3BucketAclWithReferencesInEachField(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_resource_with_references_resolved(self):
		template = load({
			'Parameters': {
				'MyCustomBucketName': {},
				'AccessControlSetting': {}
			},
			'Resources': {
				'MyBucket': {
					'Type': 'AWS::S3::Bucket',
					'Properties': {
						'BucketName': {
							'Ref': 'MyCustomBucketName'
						},
						'AccessControl': {
							'Ref': 'AccessControlSetting'
						}
					}
				}
			}
		}, parameters={
			'MyCustomBucketName': 'MyTestBucket1',
			'AccessControlSetting': 'PublicRead'
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyTestBucket1", resource.ResourceName)
		self.assertEqual('AWS::S3::Bucket', resource.ResourceType)

		self.assertEqual('BucketAcl', resource.Policy.Name)
		self.assertIsNone(resource.Policy.Policy)
		self.assertEqual("PublicRead", resource.Configuration["AccessControl"])


class WhenParsingAnS3BucketAclAndAnS3BucketPolicyWithSameName(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_a_single_resource(self):
		template = load_resources({
			'TestBucket': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'BucketName': 'MyBucket',
					'AccessControl': 'BucketOwnerFullControl'
				}
			},
			'TestBucket2': {
				'Type': 'AWS::S3::BucketPolicy',
				'Properties': {
					'Bucket': 'MyBucket',
					'PolicyDocument': s3_policy_with_no_reference
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
		self.assertEqual("BucketOwnerFullControl", resource.Configuration["AccessControl"])


class WhenParsingAnS3BucketAclAndAnS3BucketPolicyWithDifferentName(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_multiple_resources(self):
		template = load_resources({
			'TestBucket': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'BucketName': 'MyBucket',
					'AccessControl': 'BucketOwnerFullControl'
				}
			},
			'TestBucket2': {
				'Type': 'AWS::S3::BucketPolicy',
				'Properties': {
					'Bucket': 'MyBucket2',
					'PolicyDocument': s3_policy_with_no_reference
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		resource = next(resource for resource in resources if resource.ResourceName == 'MyBucket')
		self.assertEqual('AWS::S3::Bucket', resource.ResourceType)
		self.assertEqual('BucketAcl', resource.Policy.Name)
		self.assertIsNone(resource.Policy.Policy)
		self.assertEqual("BucketOwnerFullControl", resource.Configuration["AccessControl"])

		resource = next(resource for resource in resources if resource.ResourceName == 'MyBucket2')
		self.assertEqual('AWS::S3::Bucket', resource.ResourceType)
		self.assertEqual('BucketPolicy', resource.Policy.Name)
		self.assertEqual(s3_policy_with_no_reference, resource.Policy.Policy)
		self.assertEqual(0, len(resource.Configuration))


class WhenParsingAnS3BucketAclAndAnS3BucketPolicyWithDuplicateName(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_only_merges_first_resource(self):
		# this is not actually valid CloudFormation, but our goal is not to validate properties of a cfn template
		# so we just choose the first bucket / bucket policy to combine and continue
		template = load_resources({
			'TestBucket': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'BucketName': 'MyBucket',
					'AccessControl': 'BucketOwnerFullControl'
				}
			},
			'TestBucket2': {
				'Type': 'AWS::S3::BucketPolicy',
				'Properties': {
					'Bucket': 'MyBucket',
					'PolicyDocument': s3_policy_with_no_reference
				}
			},
			'TestBucket3': {
				'Type': 'AWS::S3::BucketPolicy',
				'Properties': {
					'Bucket': 'MyBucket',
					'PolicyDocument': s3_policy_with_no_reference
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		# only one of the resources was merged
		self.assertTrue(any(resource for resource in resources if len(resource.Configuration) == 0))