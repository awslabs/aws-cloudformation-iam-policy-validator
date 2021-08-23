"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest
from unittest.mock import MagicMock, patch

from botocore.stub import Stubber

from cfn_policy_validator.tests import account_config
from cfn_policy_validator.validation.validator import validate_parser_output, Validator
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.output import Output, Policy, Resource


resource_policy_with_no_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {
				'AWS': account_config.account_id
			},
			'Resource': f'arn:aws:sqs:{account_config.region}:{account_config.account_id}:resource1'
		}
	]
}

lambda_permissions_policy_with_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {},
		"Action": "lambda:InvokeFunction",
		"Resource":  f"arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:my-function"
	}]
}


class BaseResourcePolicyTest(unittest.TestCase):
	def setUp(self):
		self.output = Output(account_config)

	def add_resources_to_output(self, resource_type, resource_policy, resource_policy_2=None):
		if resource_policy_2 is None:
			resource_policy_2 = resource_policy

		policy1 = Policy('policy1', copy.deepcopy(resource_policy))
		resource1 = Resource('resource1', resource_type, policy1)

		policy2 = Policy('policy2', copy.deepcopy(resource_policy_2))
		resource2 = Resource('resource2', resource_type, policy2)

		self.output.Resources = [
			resource1,
			resource2
		]

	def assert_finding_is_equal(self, actual_finding, expected_policy_name, expected_resource_name, expected_code):
		self.assertEqual(expected_policy_name, actual_finding.policyName)
		self.assertEqual(expected_resource_name, actual_finding.resourceName)
		self.assertEqual(expected_code, actual_finding.code)

	def assert_has_findings(self, findings, errors=0, security_warnings=0, warnings=0, suggestions=0):
		self.assertEqual(errors, len(findings.errors))
		self.assertEqual(security_warnings, len(findings.security_warnings))
		self.assertEqual(warnings, len(findings.warnings))
		self.assertEqual(suggestions, len(findings.suggestions))


class WhenValidatingResources(BaseResourcePolicyTest):
	def setUp(self):
		self.output = Output(account_config)

	def test_unknown_access_preview_failure(self):
		policy = Policy('ResourcePolicy', copy.deepcopy(resource_policy_with_no_findings))
		resources = [
			Resource('resource1', 'AWS::SQS::Queue', policy)
		]

		def get_access_preview(*args, **kwargs):
			return {
				'accessPreview': {
					'status': 'FAILED',
					'statusReason': {
						'code': 'UNKNOWN_ERROR'
					}
				}
			}

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with patch.object(validator, 'client', wraps=validator.client) as mock:
			mock.get_access_preview = MagicMock(side_effect=get_access_preview)

			validator.maximum_number_of_access_preview_attempts = 2
			with self.assertRaises(ApplicationError) as cm:
				validator.validate_resources(resources)

			self.assertEqual('Failed to create access preview for resource1.  Reason: UNKNOWN_ERROR',
							 str(cm.exception))

	def test_unknown_access_preview_timeout(self):
		policy = Policy('ResourcePolicy', copy.deepcopy(resource_policy_with_no_findings))
		resources = [
			Resource('resource1', 'AWS::SQS::Queue', policy)
		]

		def get_access_preview(*args, **kwargs):
			return {
				'accessPreview': {
					'status': 'CREATING'
				}
			}

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with patch.object(validator, 'client', wraps=validator.client) as mock:
			mock.get_access_preview = MagicMock(side_effect=get_access_preview)

			validator.maximum_number_of_access_preview_attempts = 2
			with self.assertRaises(ApplicationError) as cm:
				validator.validate_resources(resources)

			self.assertEqual('Timed out after 5 minutes waiting for access analyzer preview to create.', str(cm.exception))

	def test_if_no_analyzer_exists_in_account(self):
		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with Stubber(validator.client) as stubber:
			stubber.add_response('list_analyzers', {'analyzers': []}, {'type': 'ACCOUNT'})
			stubber.add_response('create_analyzer',
								{'arn': 'arn:aws:access-analyzer:us-east-1:123456789123:analyzer/MyAnalyzer'},
								{'analyzerName': validator.access_analyzer_name, 'type': 'ACCOUNT'})
			validator.validate_resources([])
			stubber.assert_no_pending_responses()

	def test_with_resource_type_that_is_not_supported_by_access_previews(self):
		output = Output(account_config)

		policy = Policy('PermissionsPolicy', copy.deepcopy(lambda_permissions_policy_with_findings))
		resource = Resource('resource1', 'Lambda', policy)

		output.Resources = [resource]

		findings = validate_parser_output(output)

		self.assert_has_findings(findings, suggestions=1)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[0],
			expected_policy_name='PermissionsPolicy',
			expected_resource_name='resource1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)


sqs_queue_policy_that_allows_external_access = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": ["*"]
		},
		"Action": "sqs:SendMessage",
		"Resource": "*"
	}]
}

sqs_queue_policy_with_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {},
		"Action": "sqs:SendMessage",
		"Resource": "*"
	}]
}

sqs_queue_policy_with_no_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": [f'{account_config.account_id}']
		},
		"Action": "sqs:SendMessage",
		"Resource": "*"
	}]
}

sqs_queue_invalid_policy = {
"Version": "2012-10-17",
	"Statement": [{
		"Effect": {"not": "valid"},
		"Principal": {
			"AWS": [f'{account_config.account_id}']
		},
		"Action": "sqs:SendMessage",
		"Resource": "*"
	}]
}


class WhenValidatingSqsQueuePolicy(BaseResourcePolicyTest):
	def test_with_sqs_policy_that_allows_external_access(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_policy_that_allows_external_access)

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

	def test_with_sqs_policy_with_findings(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_policy_with_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, suggestions=2)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	def test_with_sqs_queue_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	def test_with_invalid_sqs_queue_policy(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_invalid_policy)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertIn("Failed to create access preview for resource1.  Validate that your trust or resource "
						 "policy's schema is correct.\nThe following validation findings were detected for this resource:", str(cm.exception))


kms_key_policy_that_allows_external_access = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": "*"
		},
		"Action": "kms:*",
		"Resource": "*"
	}]
}

kms_key_policy_with_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {},
		"Action": "kms:*",
		"Resource": "*"
	}]
}

kms_key_policy_with_no_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": f"arn:aws:iam::{account_config.account_id}:root"
		},
		"Action": "kms:*",
		"Resource": "*"
	}]
}

kms_key_invalid_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": f"arn:aws:iam::{account_config.account_id}:root"
		},
		"Action": {"not": "valid"},
		"Resource": "*"
	}]
}


class WhenValidatingKmsKeyPolicy(BaseResourcePolicyTest):
	def test_with_kms_policy_that_allows_external_access(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_policy_that_allows_external_access)

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

	def test_with_kms_policy_with_findings(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_policy_with_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, suggestions=2)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	def test_with_kms_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	def test_with_invalid_kms_policy(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_invalid_policy)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertIn("Failed to create access preview for resource1.  Validate that your trust or resource "
						 "policy's schema is correct.\nThe following validation findings were detected for this resource:", str(cm.exception))


def build_s3_bucket_policy_that_allows_external_access(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
			"Action": "*",
			"Resource": [f"arn:aws:s3:::{resource_name}", f"arn:aws:s3:::{resource_name}/*"]
		}]
	}


def build_s3_bucket_policy_with_findings(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [f"arn:aws:s3:::{resource_name}/*"]
		}]
	}


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

s3_bucket_invalid_policy = {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": {"not": "valid"}
		}]
	}


class WhenValidatingS3BucketPolicy(BaseResourcePolicyTest):
	def test_with_s3_bucket_policy_that_allows_external_access(self):
		self.add_resources_to_output('AWS::S3::Bucket',
									 build_s3_bucket_policy_that_allows_external_access('resource1'),
									 build_s3_bucket_policy_that_allows_external_access('resource2'))

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

	def test_with_s3_bucket_policy_with_findings(self):
		self.add_resources_to_output('AWS::S3::Bucket',
									 build_s3_bucket_policy_with_findings('resource1'),
									 build_s3_bucket_policy_with_findings('resource2'))

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, suggestions=2)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	def test_with_s3_bucket_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::S3::Bucket',
									 build_s3_bucket_policy_with_no_findings('resource1'),
									 build_s3_bucket_policy_with_no_findings('resource2'))

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	def test_with_invalid_s3_bucket_policy(self):
		self.add_resources_to_output('AWS::S3::Bucket', s3_bucket_invalid_policy)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertIn("Failed to create access preview for resource1.  Validate that your trust or resource "
						 "policy's schema is correct.\nThe following validation findings were detected for this resource:", str(cm.exception))


secrets_manager_resource_policy_that_allows_external_access = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": f"arn:aws:iam::777888999444:root"},
		"Action": "secretsmanager:GetSecretValue",
		"Resource": "*"
	}]
}

secrets_manager_resource_policy_with_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {},
		"Action": "secretsmanager:GetSecretValue",
		"Resource": "*"
	}]
}

secrets_manager_resource_policy_with_no_findings = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": f"arn:aws:iam::{account_config.account_id}:root"
		},
		"Action": "secretsmanager:GetSecretValue",
		"Resource": "*"
	}]
}

secrets_manager_resource_invalid_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": f"arn:aws:iam::{account_config.account_id}:root"
		},
		"Action": {"not": "valid"},
		"Resource": "*"
	}]
}


class WhenValidatingSecretsManagerResourcePolicy(BaseResourcePolicyTest):
	# This doesn't work because secrets manager uses the default KMS key if no KMS key is provided
	# the default KMS key is not publicly accessible, so the secret is therefore not publicly accessible.
	# To make this work, we'd need to look up the KMS key from the environment OR from the key policy if it had
	# yet to be created
	@unittest.skip("Need to figure out why this isn't working")
	def test_with_secrets_manager_resource_policy_that_allows_external_access(self):
		self.add_resources_to_output('AWS::SecretsManager::Secret', secrets_manager_resource_policy_that_allows_external_access)

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

	def test_with_secrets_manager_resource_policy_with_findings(self):
		self.add_resources_to_output('AWS::SecretsManager::Secret', secrets_manager_resource_policy_with_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, suggestions=2)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.suggestions[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	def test_with_secrets_manager_resource_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::SecretsManager::Secret', secrets_manager_resource_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	def test_with_invalid_secrets_manager_resource_policy(self):
		self.add_resources_to_output('AWS::SecretsManager::Secret', secrets_manager_resource_invalid_policy)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertIn("Failed to create access preview for resource1.  Validate that your trust or resource "
						 "policy's schema is correct.\nThe following validation findings were detected for this resource:", str(cm.exception))
