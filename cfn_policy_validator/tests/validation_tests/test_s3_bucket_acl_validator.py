"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
import time
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Resource, Policy
from cfn_policy_validator.tests import account_config, BotoResponse, my_canonical_user_id, end_to_end, offline_only
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.validation_tests import mock_access_analyzer_resource_setup, MockAccessPreviewFinding, \
	MockNoFindings, MockInvalidConfiguration,\
	MockAccessPreviewFindingOnly, MockSkippedFindingsAccessPreviewOnly
from cfn_policy_validator.tests.validation_tests.test_resource_validator import BaseResourcePolicyTest
from cfn_policy_validator.validation.validator import validate_parser_output, S3BucketPreviewBuilder


def build_s3_bucket_policy_with_no_findings(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [f"arn:aws:s3:::{resource_name}", f"arn:aws:s3:::{resource_name}/*"]
		}]
	}


def mock_canonical_user_id():
	return mock_node_evaluator_setup(
		s3=[
			BotoResponse(
				method='list_buckets',
				service_response={
					'Owner': {
						'ID': my_canonical_user_id
					}
				}
			)
		]
	)


class WhenValidatingS3BucketAcl(BaseResourcePolicyTest):
	@mock_canonical_user_id()
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFindingOnly(),
		MockAccessPreviewFindingOnly()
	)
	# testing this against an AWS environment requires disabling BPA
	@offline_only
	def test_with_s3_bucket_acl_that_allows_external_access(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			None,
			configuration_1={'AccessControl': 'PublicRead'}
		)

		self.has_external_access_findings()

	@mock_canonical_user_id()
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(custom_validate_policy_type='AWS::S3::Bucket'),
		MockAccessPreviewFinding(custom_validate_policy_type='AWS::S3::Bucket')
	)
	# testing this against an AWS environment requires disabling BPA
	@offline_only
	def test_with_s3_bucket_acl_and_policy_that_allows_external_access(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			build_s3_bucket_policy_with_no_findings('resource1'),
			build_s3_bucket_policy_with_no_findings('resource2'),
			configuration_1={'AccessControl': 'PublicRead'},
			configuration_2={'AccessControl': 'PublicRead'}
		)

		self.has_external_access_findings()

	def has_external_access_findings(self):
		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, security_warnings=2)
		self.assert_finding_is_equal(
			actual_finding=findings.security_warnings[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EXTERNAL_PRINCIPAL'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.security_warnings[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='EXTERNAL_PRINCIPAL'
		)

	@mock_canonical_user_id()
	@mock_access_analyzer_resource_setup(
		MockSkippedFindingsAccessPreviewOnly(),
		MockSkippedFindingsAccessPreviewOnly()
	)
	def test_with_s3_bucket_acl_with_no_findings(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			None,
			configuration_1={'AccessControl': 'Private'}
		)
		self.has_no_findings()

	@mock_canonical_user_id()
	@mock_access_analyzer_resource_setup(
		MockNoFindings(custom_validate_policy_type='AWS::S3::Bucket'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::Bucket')
	)
	def test_with_s3_bucket_acl_and_policy_with_no_findings(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			build_s3_bucket_policy_with_no_findings('resource1'),
			build_s3_bucket_policy_with_no_findings('resource2'),
			configuration_1={'AccessControl': 'Private'},
			configuration_2={'AccessControl': 'Private'}
		)
		self.has_no_findings()

	def has_no_findings(self):
		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(),
		MockInvalidConfiguration()
	)
	def test_with_invalid_s3_bucket_acl(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			None,
			configuration_1={'AccessControl': 'Invalid'}
		)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertEqual("Invalid AccessControl value \"Invalid\" for resource1."
					  "\nSee https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-bucket.html#cfn-s3-bucket-accesscontrol "
					  "for valid AccessControl values.", str(cm.exception))


class WhenBuildingS3BucketConfiguration(unittest.TestCase):
	owner_full_control = {
		'grantee': {
			'id': my_canonical_user_id
		},
		'permission': 'FULL_CONTROL'
	}

	all_users_read = {
		'grantee': {
			'uri': 'http://acs.amazonaws.com/groups/global/AllUsers'
		},
		'permission': 'READ'
	}

	all_users_write = {
		'grantee': {
			'uri': 'http://acs.amazonaws.com/groups/global/AllUsers'
		},
		'permission': 'WRITE'
	}

	authenticated_users_read = {
		'grantee': {
			'uri': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
		},
		'permission': 'READ'
	}

	log_delivery_write = {
		'grantee': {
			'uri': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
		},
		'permission': 'WRITE'
	}

	log_delivery_read_acp = {
		'grantee': {
			'uri': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
		},
		'permission': 'READ_ACP'
	}

	ec2_read = {
		'grantee': {
			'id': '6aa5a366c34c1cbe25dc49211496e913e0351eb0e8c37aa3477e40942ec6b97c'
		},
		'permission': 'READ'
	}

	@staticmethod
	def build_resource(access_control, policy=None):
		if policy is None:
			policy = Policy('BucketAcl', None)

		return Resource(
			resource_name='resource1',
			resource_type='AWS::S3::Bucket',
			policy=policy,
			configuration={'AccessControl': access_control}
		)

	def assert_valid_configuration(self, access_control, expected_grants, policy=None):
		builder = S3BucketPreviewBuilder(account_config.region, account_config.partition)
		resource = self.build_resource(access_control, policy)
		configuration = builder.build_configuration(resource)
		arn_config = configuration[f'arn:{account_config.partition}:s3:::resource1']
		s3_bucket = arn_config['s3Bucket']
		actual_acl_grants = s3_bucket['bucketAclGrants']

		self.assertCountEqual(actual_acl_grants, expected_grants)

	@mock_canonical_user_id()
	def test_build_configuration_for_private_acl(self):
		self.assert_valid_configuration(
			'Private',
			[
				self.owner_full_control
			])

	@mock_canonical_user_id()
	def test_build_configuration_for_public_read_acl(self):
		self.assert_valid_configuration(
			'PublicRead',
			[
				self.owner_full_control,
				self.all_users_read
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_public_read_write_acl(self):
		self.assert_valid_configuration(
			'PublicReadWrite',
			[
				self.owner_full_control,
				self.all_users_read,
				self.all_users_write
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_authenticated_read_acl(self):
		self.assert_valid_configuration(
			'AuthenticatedRead',
			[
				self.owner_full_control,
				self.authenticated_users_read
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_log_delivery_write_acl(self):
		self.assert_valid_configuration(
			'LogDeliveryWrite',
			[
				self.log_delivery_write,
				self.log_delivery_read_acp
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_bucket_owner_read_acl(self):
		self.assert_valid_configuration(
			'BucketOwnerRead',
			[
				self.owner_full_control
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_bucket_owner_full_control_acl(self):
		self.assert_valid_configuration(
			'BucketOwnerFullControl',
			[
				self.owner_full_control
			]
		)

	@mock_canonical_user_id()
	def test_build_configuration_for_aws_exec_read_acl(self):
		self.assert_valid_configuration(
			'AwsExecRead',
			[
				self.owner_full_control,
				self.ec2_read
			]
		)

	def test_build_invalid_configuration(self):
		builder = S3BucketPreviewBuilder(account_config.region, account_config.partition)
		resource = self.build_resource('Invalid')

		with self.assertRaises(ApplicationError) as cm:
			builder.build_configuration(resource)

		self.assertEqual("Invalid AccessControl value \"Invalid\" for resource1."
					  "\nSee https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-bucket.html#cfn-s3-bucket-accesscontrol "
					  "for valid AccessControl values.", str(cm.exception))

	@mock_canonical_user_id()
	def test_build_configuration_with_access_control_and_policy(self):
		self.assert_valid_configuration(
			'Private',
			[self.owner_full_control],
			policy=Policy('BucketPolicy', build_s3_bucket_policy_with_no_findings('resource1'))
		)


class WhenValidatingCannedAclConfigurations(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(WhenValidatingCannedAclConfigurations, self).__init__(*args, **kwargs)
		self.client = None
		self.analyzer_arn = None
		self.maximum_number_of_access_preview_attempts = 10

	def build_client(self):
		if self.client is None:
			self.client = boto3.client('accessanalyzer')

		if self.analyzer_arn is None:
			response = self.client.list_analyzers(type='ACCOUNT')
			self.analyzer_arn = next(analyzer['arn'] for analyzer in response['analyzers'] if analyzer['status'] == 'ACTIVE')

	@staticmethod
	def build_resource(access_control, policy=None):
		if policy is None:
			policy = Policy('BucketAcl', None)

		return Resource(
			resource_name='resource1',
			resource_type='AWS::S3::Bucket',
			policy=policy,
			configuration={'AccessControl': access_control}
		)

	def build_configuration(self, access_control, policy=None):
		builder = S3BucketPreviewBuilder(account_config.region, account_config.partition)
		resource = self.build_resource(access_control, policy)
		return builder.build_configuration(resource)

	def wait_for_access_preview_response(self, access_preview_id):
		number_of_attempts = 0
		while True:
			response = self.client.get_access_preview(
				accessPreviewId=access_preview_id,
				analyzerArn=self.analyzer_arn
			)
			status = response['accessPreview']['status']

			if status == 'CREATING':
				number_of_attempts = number_of_attempts + 1
				if number_of_attempts >= self.maximum_number_of_access_preview_attempts:
					raise Exception(f'Timed out after 5 minutes waiting for access analyzer preview to create.')

				time.sleep(2)
			else:
				return response

	def run_test_access_preview(self, access_control):
		# this is intentionally called within the test to ensure we only build the client when tests are run in end
		# to end mode
		self.build_client()

		configuration = self.build_configuration(access_control)
		response = self.client.create_access_preview(
			analyzerArn=self.analyzer_arn,
			configurations=configuration
		)
		response = self.wait_for_access_preview_response(response['id'])
		self.assertEqual('COMPLETED', response['accessPreview']['status'])

	# these tests validate that we crafted valid configuration, no need to run outside of end to end mode.  We want to
	# hit the actual access analyzer endpoint
	@end_to_end
	def test_create_access_preview_private(self):
		self.run_test_access_preview('Private')

	@end_to_end
	def test_create_access_preview_public_read(self):
		self.run_test_access_preview('PublicRead')

	@end_to_end
	def test_create_access_preview_public_read_write(self):
		self.run_test_access_preview('PublicReadWrite')

	@end_to_end
	def test_create_access_preview_authenticated_read(self):
		self.run_test_access_preview('AuthenticatedRead')

	@end_to_end
	def test_create_access_preview_log_delivery_write(self):
		self.run_test_access_preview('LogDeliveryWrite')

	@end_to_end
	def test_create_access_preview_bucket_owner_read(self):
		self.run_test_access_preview('BucketOwnerRead')

	@end_to_end
	def test_create_access_preview_bucket_owner_full_control(self):
		self.run_test_access_preview('BucketOwnerFullControl')

	@end_to_end
	def test_create_access_preview_aws_exec_read(self):
		self.run_test_access_preview('AwsExecRead')
