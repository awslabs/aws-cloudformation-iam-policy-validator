"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import ApplicationError
from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.validation_tests import mock_access_analyzer_resource_setup, MockAccessPreviewFinding, \
	MockValidateResourcePolicyFinding, MockNoFindings, MockInvalidConfiguration, FINDING_TYPE, MockBadRequest
from cfn_policy_validator.tests.validation_tests.test_resource_validator import BaseResourcePolicyTest
from cfn_policy_validator.validation.validator import validate_parser_output


def build_s3_access_point_policy_that_allows_external_access(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
			"Action": "*",
			"Resource": [
				f"arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{resource_name}",
				f"arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{resource_name}/object/*"
			]
		}]
	}


def build_s3_access_point_policy_with_findings(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [
				f"arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{resource_name}/object/*"
			]
		}]
	}


def build_s3_access_point_policy_with_no_findings(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [
				f"arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{resource_name}",
				f"arn:aws:s3:{account_config.region}:{account_config.account_id}:accesspoint/{resource_name}/object/*"
			]
		}]
	}


s3_access_point_invalid_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
		"Action": ["s3:PutObject", "s3:PutObjectAcl"],
		"Resource": "arn:aws:s3:::notvalid"
	}]
}

access_point_configuration = {
	'VpcId': 'vpc-010e1791024eb0af9'
}


class WhenValidatingS3AccessPointPolicy(BaseResourcePolicyTest):
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::AccessPoint'),
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_that_allows_external_access_with_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_that_allows_external_access('resource1'),
			build_s3_access_point_policy_that_allows_external_access('resource2'),
			access_point_configuration,
			access_point_configuration
		)

		self.has_external_access_findings()

	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::AccessPoint'),
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_that_allows_external_access_without_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_that_allows_external_access('resource1'),
			build_s3_access_point_policy_that_allows_external_access('resource2')
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

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::AccessPoint'),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_with_findings_with_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_with_findings('resource1'),
			build_s3_access_point_policy_with_findings('resource2'),
			access_point_configuration,
			access_point_configuration
		)

		self.has_findings()

	@mock_access_analyzer_resource_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::AccessPoint'),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_with_findings_without_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_with_findings('resource1'),
			build_s3_access_point_policy_with_findings('resource2')
		)

		self.has_findings()

	def has_findings(self):
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
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_with_no_findings_with_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_with_no_findings('resource1'),
			build_s3_access_point_policy_with_no_findings('resource2'),
			access_point_configuration,
			access_point_configuration
		)
		self.has_no_findings()

	@mock_access_analyzer_resource_setup(
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_s3_access_point_policy_with_no_findings_without_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_with_no_findings('resource1'),
			build_s3_access_point_policy_with_no_findings('resource2')
		)
		self.has_no_findings()

	def has_no_findings(self):
		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidConfiguration(code='UNSUPPORTED_RESOURCE_ARN_IN_POLICY'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_invalid_s3_access_point_policy(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			s3_access_point_invalid_policy,
			build_s3_access_point_policy_with_no_findings('resource2')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='UNSUPPORTED_RESOURCE_ARN_IN_POLICY'
		)

	@mock_access_analyzer_resource_setup(
		MockBadRequest(custom_validate_policy_type='AWS::S3::AccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::AccessPoint')
	)
	def test_with_invalid_s3_access_point_vpc_id(self):
		self.add_resources_to_output(
			'AWS::S3::AccessPoint',
			build_s3_access_point_policy_with_no_findings('resource1'),
			build_s3_access_point_policy_with_no_findings('resource2'),
			{'VpcId': 'NotAValidVpc'},
			access_point_configuration
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)
