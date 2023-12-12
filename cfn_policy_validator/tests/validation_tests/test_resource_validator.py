"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
import copy
import unittest

from botocore.stub import ANY

from cfn_policy_validator.tests import account_config, offline_only, only_run_for_end_to_end
from cfn_policy_validator.tests.boto_mocks import mock_test_setup, BotoResponse, get_test_mode, TEST_MODE
from cfn_policy_validator.tests.validation_tests import FINDING_TYPE, mock_access_analyzer_resource_setup, \
	MockAccessPreviewFinding, MockNoFindings, MockInvalidConfiguration, MockUnknownError, \
	MockTimeout, MockValidateResourcePolicyFinding
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

	def add_resources_to_output(self, resource_type, resource_policy, resource_policy_2=None, configuration_1=None, configuration_2=None):
		if resource_policy_2 is None:
			resource_policy_2 = resource_policy

		policy1 = Policy('policy1', copy.deepcopy(resource_policy))
		resource1 = Resource('resource1', resource_type, policy1, configuration_1)

		policy2 = Policy('policy2', copy.deepcopy(resource_policy_2))
		resource2 = Resource('resource2', resource_type, policy2, configuration_2)

		self.output.Resources = [
			resource1,
			resource2
		]

	@only_run_for_end_to_end
	def create_archive_rule(self, resource_type_to_archive):
		session = boto3.Session(region_name=account_config.region)
		self.client = session.client('accessanalyzer')
		response = self.client.list_analyzers(type='ACCOUNT')
		self.actual_analyzer_name = next((analyzer['name'] for analyzer in response['analyzers'] if analyzer['status'] == 'ACTIVE'))
		self.archive_rule_name = 'IgnoreRoleFindings'
		self.client.create_archive_rule(
			analyzerName=self.actual_analyzer_name,
			ruleName='IgnoreRoleFindings',
			filter={
				'resourceType': {
					'eq': [resource_type_to_archive]
				}
			}
		)

	@only_run_for_end_to_end
	def delete_archive_rule(self):
		self.client.delete_archive_rule(analyzerName=self.actual_analyzer_name, ruleName=self.archive_rule_name)

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

	@mock_access_analyzer_resource_setup(
		MockUnknownError()
	)
	@offline_only
	def test_unknown_access_preview_failure(self):
		policy = Policy('ResourcePolicy', copy.deepcopy(resource_policy_with_no_findings))
		resources = [
			Resource('resource1', 'AWS::SQS::Queue', policy)
		]

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with self.assertRaises(ApplicationError) as cm:
			validator.validate_resources(resources)

		self.assertEqual('Failed to create access preview for resource1.  Reason: UNKNOWN_ERROR', str(cm.exception))

	@mock_access_analyzer_resource_setup(
		MockTimeout()
	)
	@offline_only
	def test_unknown_access_preview_timeout(self):
		policy = Policy('ResourcePolicy', copy.deepcopy(resource_policy_with_no_findings))
		resources = [
			Resource('resource1', 'AWS::SQS::Queue', policy)
		]

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		validator.maximum_number_of_access_preview_attempts = 2
		with self.assertRaises(ApplicationError) as cm:
			validator.validate_resources(resources)

		self.assertEqual('Timed out after 5 minutes waiting for access analyzer preview to create.', str(cm.exception))

	@mock_test_setup(
		accessanalyzer=[
			BotoResponse(
				method='list_analyzers',
				service_response={'analyzers': []},
				expected_params={'type': 'ACCOUNT'}
			),
			BotoResponse(
				method='create_analyzer',
				service_response={'arn': 'arn:aws:access-analyzer:us-east-1:123456789123:analyzer/MyAnalyzer'},
				expected_params={'analyzerName': ANY, 'type': 'ACCOUNT'}
			)
		],
		assert_no_pending_responses=True
	)
	def test_if_no_analyzer_exists_in_account(self):
		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		validator.validate_resources([])

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION)
	)
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


class WhenValidatingResourcesWithNonActiveFindings(BaseResourcePolicyTest):
	def setUp(self):
		self.output = Output(account_config)
		self.create_archive_rule(resource_type_to_archive='AWS::KMS::Key')

	def tearDown(self):
		self.delete_archive_rule()

	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(),
		MockAccessPreviewFinding(finding_status='ARCHIVED')
	)
	def test_output_only_includes_active_findings(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_policy_that_allows_external_access)
		policy1 = Policy('policy1', copy.deepcopy(sqs_queue_policy_that_allows_external_access))
		resource1 = Resource('resource1', 'AWS::SQS::Queue', policy1)

		policy2 = Policy('policy2', copy.deepcopy(kms_key_policy_that_allows_external_access))
		resource2 = Resource('resource2', 'AWS::KMS::Key', policy2)

		self.output.Resources = [resource1, resource2]

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, security_warnings=1)
		self.assert_finding_is_equal(
			actual_finding=findings.security_warnings[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='EXTERNAL_PRINCIPAL'
		)

	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(finding_status='ARCHIVED'),
		MockAccessPreviewFinding(finding_status='ARCHIVED')
	)
	def test_output_does_not_include_any_findings_when_all_are_archived(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_policy_that_allows_external_access)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, security_warnings=0)


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
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(),
		MockAccessPreviewFinding()
	)
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

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION)
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

	@mock_access_analyzer_resource_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_with_sqs_queue_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::SQS::Queue', sqs_queue_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(code='DATA_TYPE_MISMATCH'),
		MockNoFindings()
	)
	def test_with_invalid_sqs_queue_policy(self):
		self.add_resources_to_output(
			'AWS::SQS::Queue',
			sqs_queue_invalid_policy,
			sqs_queue_policy_with_no_findings
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)

		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)


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
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(),
		MockAccessPreviewFinding()
	)
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

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION)
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

	@mock_access_analyzer_resource_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_with_kms_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::KMS::Key', kms_key_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(code='DATA_TYPE_MISMATCH'),
		MockNoFindings()
	)
	def test_with_invalid_kms_policy(self):
		self.add_resources_to_output(
			'AWS::KMS::Key',
			kms_key_invalid_policy,
			kms_key_policy_with_no_findings
		)
		findings = validate_parser_output(self.output)

		self.assert_has_findings(findings, errors=1)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)


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
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(custom_validate_policy_type='AWS::S3::Bucket'),
		MockAccessPreviewFinding(custom_validate_policy_type='AWS::S3::Bucket')
	)
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

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::Bucket'),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::Bucket')
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

	@mock_access_analyzer_resource_setup(
		MockNoFindings(custom_validate_policy_type='AWS::S3::Bucket'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::Bucket')
	)
	def test_with_s3_bucket_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::S3::Bucket',
									 build_s3_bucket_policy_with_no_findings('resource1'),
									 build_s3_bucket_policy_with_no_findings('resource2'))

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(code='DATA_TYPE_MISMATCH'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::Bucket')
	)
	def test_with_invalid_s3_bucket_policy(self):
		self.add_resources_to_output(
			'AWS::S3::Bucket',
			s3_bucket_invalid_policy,
			build_s3_bucket_policy_with_no_findings('resource2')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)


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
	@unittest.skip("Skip until this is supported")
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

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION)
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

	@mock_access_analyzer_resource_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_with_secrets_manager_resource_policy_with_no_findings(self):
		self.add_resources_to_output('AWS::SecretsManager::Secret', secrets_manager_resource_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(code='DATA_TYPE_MISMATCH'),
		MockNoFindings()
	)
	def test_with_invalid_secrets_manager_resource_policy(self):
		self.add_resources_to_output(
			'AWS::SecretsManager::Secret',
			secrets_manager_resource_invalid_policy,
			secrets_manager_resource_policy_with_no_findings
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)
