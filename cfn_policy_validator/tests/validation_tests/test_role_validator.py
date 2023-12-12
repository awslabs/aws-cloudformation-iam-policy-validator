"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from botocore.stub import ANY

from cfn_policy_validator.tests import account_config, offline_only
from cfn_policy_validator.tests.boto_mocks import mock_test_setup, BotoResponse
from cfn_policy_validator.tests.validation_tests import MockAccessPreviewFinding, \
	FINDING_TYPE, MockNoFindings, MockInvalidConfiguration, MockValidateResourcePolicyFinding, \
	MockValidateIdentityPolicyFinding, mock_access_analyzer_role_setup, MockValidateIdentityAndResourcePolicyFinding, \
	MockUnknownError, MockTimeout
from cfn_policy_validator.validation.validator import validate_parser_output, Validator
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.output import Output, Role, Policy

trust_policy_that_allows_external_access = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {
				'AWS': '*'
			}
		}
	]
}


trust_policy_with_no_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {
				'AWS': account_config.account_id
			}
		}
	]
}

trust_policy_with_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {}
		}
	]
}

invalid_trust_policy = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {
				'AWS': {
					'Fn::UnsupportedKey': 'Value'
				}
			}
		}
	]
}

identity_policy_with_no_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': 'iam:ListRoles',
			'Resource': '*'
		}
	]
}


identity_policy_with_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': 'iam:PassRole',
			'Resource': '*'
		}
	]
}


invalid_identity_policy = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': 'iam:PassRole',
			'Resource': {
				'NotAValid': 'Resource'
			}
		}
	]
}

trust_policy_validate_policy_resource_type = 'AWS::IAM::AssumeRolePolicyDocument'


class WhenValidatingRoles(unittest.TestCase):
	def setUp(self):
		self.output = Output(account_config)

	def assert_role_finding_is_equal(self, actual_role_finding, expected_policy_name, expected_resource_name, expected_code):
		self.assertEqual(expected_policy_name, actual_role_finding.policyName)
		self.assertEqual(expected_resource_name, actual_role_finding.resourceName)
		self.assertEqual(expected_code, actual_role_finding.code)

	def assert_has_findings(self, findings, errors=0, security_warnings=0, warnings=0, suggestions=0):
		self.assertEqual(len(findings.errors), errors)
		self.assertEqual(len(findings.security_warnings), security_warnings)
		self.assertEqual(len(findings.warnings), warnings)
		self.assertEqual(len(findings.suggestions), suggestions)

	def add_roles_to_output(self, trust_policy, trust_policy_2=None, identity_policy=None, role_1_name='role1'):
		if trust_policy_2 is None:
			trust_policy_2 = trust_policy

		role1 = Role(role_1_name, role_path="/", trust_policy=copy.deepcopy(trust_policy))
		if identity_policy is None:
			identity_policy = identity_policy_with_no_findings

		role1.add_policy(Policy('Policy1', copy.deepcopy(identity_policy)))

		role2 = Role('role2', role_path='/', trust_policy=copy.deepcopy(trust_policy_2))
		if identity_policy is None:
			identity_policy = identity_policy_with_no_findings

		role2.add_policy(Policy('Policy2', copy.deepcopy(identity_policy)))

		self.output.Roles = [
			role1,
			role2
		]

	@mock_access_analyzer_role_setup(
		MockAccessPreviewFinding(custom_validate_policy_type=trust_policy_validate_policy_resource_type),
		MockAccessPreviewFinding(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_trust_policy_that_allows_external_access(self):
		self.add_roles_to_output(trust_policy=trust_policy_that_allows_external_access)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, security_warnings=2)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.security_warnings[0],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role1',
			expected_code='EXTERNAL_PRINCIPAL'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.security_warnings[1],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role2',
			expected_code='EXTERNAL_PRINCIPAL'
		)

	@mock_access_analyzer_role_setup(
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type=trust_policy_validate_policy_resource_type),
		MockValidateResourcePolicyFinding(code='EMPTY_OBJECT_PRINCIPAL', finding_type=FINDING_TYPE.SUGGESTION, custom_resource_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_trust_policy_with_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, suggestions=2)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.suggestions[0],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.suggestions[1],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	@mock_access_analyzer_role_setup(
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type),
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_trust_policy_with_no_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_role_setup(
		MockInvalidConfiguration(code='DATA_TYPE_MISMATCH'),
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_invalid_trust_policy(self):
		self.add_roles_to_output(
			trust_policy=invalid_trust_policy,
			trust_policy_2=trust_policy_with_no_findings
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[0],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role1',
			expected_code='DATA_TYPE_MISMATCH'
		)

	@mock_access_analyzer_role_setup(
		MockInvalidConfiguration(finding_type='WARNING'),
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	# unsure how to replicate this specific scenario
	@offline_only
	def test_with_invalid_role_trust_policy_and_no_error_findings(self):
		self.add_roles_to_output(trust_policy=invalid_trust_policy)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=1, warnings=1)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[0],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role1',
			expected_code='FAILED_ACCESS_PREVIEW_CREATION'
		)

	@mock_access_analyzer_role_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING)
	)
	def test_with_identity_policy_with_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings, identity_policy=identity_policy_with_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, security_warnings=2)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.security_warnings[0],
			expected_policy_name='Policy1',
			expected_resource_name='role1',
			expected_code='PASS_ROLE_WITH_STAR_IN_RESOURCE'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.security_warnings[1],
			expected_policy_name='Policy2',
			expected_resource_name='role2',
			expected_code='PASS_ROLE_WITH_STAR_IN_RESOURCE'
		)

	@mock_access_analyzer_role_setup(
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type),
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_identity_policy_with_no_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings, identity_policy=identity_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_role_setup(
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR),
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR)
	)
	def test_with_invalid_identity_policy(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings, identity_policy=invalid_identity_policy)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[0],
			expected_policy_name='Policy1',
			expected_resource_name='role1',
			expected_code='DATA_TYPE_MISMATCH'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[1],
			expected_policy_name='Policy2',
			expected_resource_name='role2',
			expected_code='DATA_TYPE_MISMATCH'
		)

	@mock_access_analyzer_role_setup(
		MockNoFindings(
			expected_params_create_access_preview={
				'analyzerArn': ANY,
				'configurations': {
					f'arn:aws:iam::{account_config.account_id}:role/ResourceA1234567891234567891234567891234567891234567891234567891': {
						'iamRole': ANY
					}
				}
			},
			custom_validate_policy_type=trust_policy_validate_policy_resource_type
		),
		MockNoFindings(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	def test_with_role_name_that_exceeds_limit(self):
		self.add_roles_to_output(
			role_1_name='ResourceA123456789123456789123456789123456789123456789123456789123456789',
			trust_policy=trust_policy_with_no_findings,
			identity_policy=identity_policy_with_no_findings
		)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	@mock_access_analyzer_role_setup(
		MockValidateIdentityAndResourcePolicyFinding(
			resource_code='EMPTY_OBJECT_PRINCIPAL', resource_finding_type=FINDING_TYPE.SUGGESTION,
			identity_code='DATA_TYPE_MISMATCH', identity_finding_type=FINDING_TYPE.ERROR,
			custom_resource_type=trust_policy_validate_policy_resource_type
		),
		MockValidateIdentityAndResourcePolicyFinding(
			resource_code='EMPTY_OBJECT_PRINCIPAL', resource_finding_type=FINDING_TYPE.SUGGESTION,
			identity_code='DATA_TYPE_MISMATCH', identity_finding_type=FINDING_TYPE.ERROR,
			custom_resource_type=trust_policy_validate_policy_resource_type
		)
	)
	def test_with_findings_in_both_trust_policy_and_identity_policy(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_findings, identity_policy=invalid_identity_policy)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings, errors=2, suggestions=2)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[0],
			expected_policy_name='Policy1',
			expected_resource_name='role1',
			expected_code='DATA_TYPE_MISMATCH'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.errors[1],
			expected_policy_name='Policy2',
			expected_resource_name='role2',
			expected_code='DATA_TYPE_MISMATCH'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.suggestions[0],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role1',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)
		self.assert_role_finding_is_equal(
			actual_role_finding=findings.suggestions[1],
			expected_policy_name='TrustPolicy',
			expected_resource_name='role2',
			expected_code='EMPTY_OBJECT_PRINCIPAL'
		)

	@mock_access_analyzer_role_setup(
		MockUnknownError(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	@offline_only
	def test_unknown_access_preview_failure(self):
		role = Role('role1', role_path="/", trust_policy=copy.deepcopy(trust_policy_with_no_findings))
		role.add_policy(Policy('Policy1', copy.deepcopy(identity_policy_with_no_findings)))

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with self.assertRaises(ApplicationError) as cm:
			validator.validate_roles([role])

		self.assertEqual('Failed to create access preview for role1.  Reason: UNKNOWN_ERROR', str(cm.exception))

	@mock_access_analyzer_role_setup(
		MockTimeout(custom_validate_policy_type=trust_policy_validate_policy_resource_type)
	)
	@offline_only
	def test_unknown_access_preview_timeout(self):
		role = Role('role1', role_path="/", trust_policy=copy.deepcopy(trust_policy_with_no_findings))
		role.add_policy(Policy('Policy1', copy.deepcopy(identity_policy_with_no_findings)))

		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		validator.maximum_number_of_access_preview_attempts = 2
		with self.assertRaises(ApplicationError) as cm:
			validator.validate_roles([role])

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
		validator.validate_roles([])
