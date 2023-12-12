"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import json
import unittest

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource
from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.validation_tests import mock_access_analyzer_resource_setup, MockAccessPreviewFinding, \
	MockValidateResourcePolicyFinding, MockNoFindings, MockInvalidConfiguration, FINDING_TYPE, \
	MockInvalidAccessPreviewSetup
from cfn_policy_validator.tests.validation_tests.test_resource_validator import BaseResourcePolicyTest
from cfn_policy_validator.validation import InvalidPolicyException
from cfn_policy_validator.validation.validator import validate_parser_output, S3MultiRegionAccessPointPreviewBuilder


def build_s3_multi_region_access_point_policy_that_allows_external_access(alias):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
			"Action": "*",
			"Resource": [
				f"arn:aws:s3::{account_config.account_id}:accesspoint/{alias}",
				f"arn:aws:s3::{account_config.account_id}:accesspoint/{alias}/object/*"
			]
		}]
	}


def build_s3_multi_region_access_point_policy_with_findings(resource_name):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [
				f"arn:aws:s3::{account_config.account_id}:accesspoint/{resource_name}/object/*"
			]
		}]
	}


def build_s3_multi_region_access_point_policy_with_no_findings(alias):
	return {
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
			"Action": ["s3:PutObject", "s3:PutObjectAcl"],
			"Resource": [
				f"arn:aws:s3::{account_config.account_id}:accesspoint/{alias}",
				f"arn:aws:s3::{account_config.account_id}:accesspoint/{alias}/object/*"
			]
		}]
	}

s3_multi_region_access_point_invalid_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
		"Action": ["s3:PutObject", "s3:PutObjectAcl"],
		"Resource": "arn:aws:s3:::notvalid"
	}]
}


class WhenValidatingS3MultiRegionAccessPointPolicy(BaseResourcePolicyTest):
	@mock_access_analyzer_resource_setup(
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'),
		MockAccessPreviewFinding(source_type='S3_ACCESS_POINT', custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_access_point_policy_that_allows_external_access(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			build_s3_multi_region_access_point_policy_that_allows_external_access('resource1.mrap'),
			build_s3_multi_region_access_point_policy_that_allows_external_access('resource2.mrap')
		)

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
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::MultiRegionAccessPoint'),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_access_point_policy_with_findings(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			build_s3_multi_region_access_point_policy_with_findings('resource1.mrap'),
			build_s3_multi_region_access_point_policy_with_findings('resource2.mrap')
		)

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
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_access_point_policy_with_no_findings(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			build_s3_multi_region_access_point_policy_with_no_findings('resource1.mrap'),
			build_s3_multi_region_access_point_policy_with_no_findings('resource2.mrap')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidAccessPreviewSetup(
			code='UNSUPPORTED_RESOURCE_ARN_IN_POLICY',
			custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'
		),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_invalid_access_point_arn(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			s3_multi_region_access_point_invalid_policy,
			build_s3_multi_region_access_point_policy_with_no_findings('resource2.mrap')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='UNSUPPORTED_RESOURCE_ARN_IN_POLICY'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[1],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)

	@mock_access_analyzer_resource_setup(
		MockInvalidAccessPreviewSetup(
			code='MISSING_STATEMENT',
			custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'
		),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_no_statements(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17"
			},
			build_s3_multi_region_access_point_policy_with_no_findings('resource2.mrap')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='MISSING_STATEMENT'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[1],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)

	@mock_access_analyzer_resource_setup(
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_single_statement_as_dict(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
					"Action": ["s3:PutObject", "s3:PutObjectAcl"],
					"Resource": [
						f"arn:aws:s3::{account_config.account_id}:accesspoint/test.mrap",
						f"arn:aws:s3::{account_config.account_id}:accesspoint/test.mrap/object/*"
					]
				}
			}
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidAccessPreviewSetup(
			code='DATA_TYPE_MISMATCH',
			custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'
		),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_statement_of_invalid_type(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17",
				"Statement": "invalid"
			},
			build_s3_multi_region_access_point_policy_with_no_findings('resource2.mrap')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[1],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)

	@mock_access_analyzer_resource_setup(
		MockInvalidAccessPreviewSetup(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'),
		MockInvalidAccessPreviewSetup(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_no_resource(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
					"Action": ["s3:PutObject", "s3:PutObjectAcl"]
				}
			}
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[1],
			expected_policy_name='policy2',
			expected_resource_name='resource2',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)

	@mock_access_analyzer_resource_setup(
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_single_resource(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
					"Action": ["s3:PutObject", "s3:PutObjectAcl"],
					"Resource": f"arn:aws:s3::{account_config.account_id}:accesspoint/test.mrap/object/*"
				}
			}
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_resource_setup(
		MockInvalidAccessPreviewSetup(
			code='DATA_TYPE_MISMATCH',
			custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint'
		),
		MockNoFindings(custom_validate_policy_type='AWS::S3::MultiRegionAccessPoint')
	)
	def test_with_s3_multi_region_access_point_policy_with_resource_of_invalid_type(self):
		self.add_resources_to_output(
			'AWS::S3::MultiRegionAccessPoint',
			{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Principal": {"AWS": [f"arn:aws:iam::{account_config.account_id}:root"]},
					"Action": ["s3:PutObject", "s3:PutObjectAcl"],
					"Resource": {"Im": "Invalid"}
				}
			},
			build_s3_multi_region_access_point_policy_with_no_findings('resource2.mrap')
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[0],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='DATA_TYPE_MISMATCH'
		)
		self.assert_finding_is_equal(
			actual_finding=findings.errors[1],
			expected_policy_name='policy1',
			expected_resource_name='resource1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)


class WhenBuildingMultiRegionAccessPointArn(unittest.TestCase):
	def setUp(self):
		self.access_point_name = 'MyAccessPoint'
		self.access_point_alias = 'abcdefg.mrap'
		self.preview_builder = S3MultiRegionAccessPointPreviewBuilder(account_config.account_id, account_config.partition)

	def test_when_policy_has_no_statement(self):
		access_point_policy = {
			"Version": "2012-10-17"
		}
		with self.assertRaises(InvalidPolicyException):
			self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)

	def test_when_statement_is_invalid_type(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": "Invalid"
		}
		with self.assertRaises(InvalidPolicyException):
			self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)

	def test_when_statement_is_dict(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": {
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}"
				]
			}
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_statement_is_list(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}"
				]
			}]
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_statement_has_no_resource(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*"
			}]
		}
		with self.assertRaises(InvalidPolicyException):
			self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)

	def test_when_resource_is_invalid_type(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": "NotValid"
			}]
		}
		with self.assertRaises(InvalidPolicyException):
			self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)

	def test_when_resource_arn_is_invalid_format(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s4::{account_config.account_id}:accesspoint/{self.access_point_alias}"
				]
			}]
		}
		with self.assertRaises(InvalidPolicyException):
			self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)

	def test_when_resource_is_string(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}"
			}]
		}

		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_resource_is_list(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}",
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}/object/*"
				]
			}]
		}

		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_resource_is_bucket(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}"
				]
			}]
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_resource_is_all_objects(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}/object/*"
				]
			}]
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_resource_is_specific_object(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}/object/MyObject"
				]
			}]
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')

	def test_when_resource_is_subset_of_objects(self):
		access_point_policy = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {'AWS': "arn:aws:iam::123456789123:role/MyOtherRole"},
				"Action": "*",
				"Resource": [
					f"arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}/object/MyObjects/*"
				]
			}]
		}
		access_point_arn = self.preview_builder.build_access_point_arn(self.access_point_name, access_point_policy)
		self.assertEqual(access_point_arn, f'arn:aws:s3::{account_config.account_id}:accesspoint/{self.access_point_alias}')
