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
from cfn_policy_validator.parsers.output import Output, Role, Policy

trust_policy_that_allows_external_access = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {
				'AWS': '*'
			},
			'Resource': '*'
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
			},
			'Resource': '*'
		}
	]
}

trust_policy_with_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': '*',
			'Principal': {},
			'Resource': '*'
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
				'AwS': account_config.account_id
			},
			'Resource': '*'
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


class WhenValidatingRoles(unittest.TestCase):
	def setUp(self):
		self.output = Output(account_config)

	def assert_role_finding_is_equal(self, actual_role_finding, expected_policy_name, expected_resource_name, expected_code):
		self.assertEqual(expected_policy_name, actual_role_finding.policyName)
		self.assertEqual(expected_resource_name, actual_role_finding.resourceName)
		self.assertEqual(expected_code, actual_role_finding.code)

	def assert_has_findings(self, findings, errors=0, security_warnings=0, warnings=0, suggestions=0):
		self.assertEqual(errors, len(findings.errors))
		self.assertEqual(security_warnings, len(findings.security_warnings))
		self.assertEqual(warnings, len(findings.warnings))
		self.assertEqual(suggestions, len(findings.suggestions))

	def add_roles_to_output(self, trust_policy, identity_policy=None):
		role1 = Role('role1', role_path="/", trust_policy=copy.deepcopy(trust_policy))
		if identity_policy is not None:
			role1.add_policy(Policy('Policy1', copy.deepcopy(identity_policy)))

		role2 = Role('role2', role_path='/', trust_policy=copy.deepcopy(trust_policy))
		if identity_policy is not None:
			role2.add_policy(Policy('Policy2', copy.deepcopy(identity_policy)))

		self.output.Roles = [
			role1,
			role2
		]

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

	def test_with_trust_policy_with_no_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

	def test_with_invalid_trust_policy(self):
		self.add_roles_to_output(trust_policy=invalid_trust_policy)

		with self.assertRaises(ApplicationError) as cm:
			validate_parser_output(self.output)

		self.assertIn("Failed to create access preview for role1.  Validate that your trust or resource "
						 "policy's schema is correct.\nThe following validation findings were detected for this resource:", str(cm.exception))

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

	def test_with_identity_policy_with_no_findings(self):
		self.add_roles_to_output(trust_policy=trust_policy_with_no_findings, identity_policy=identity_policy_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assert_has_findings(findings)

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

	def test_unknown_access_preview_failure(self):
		roles = [
			Role('role1', role_path="/", trust_policy=copy.deepcopy(trust_policy_with_no_findings))
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
				validator.validate_roles(roles)

			self.assertEqual('Failed to create access preview for role1.  Reason: UNKNOWN_ERROR',
							 str(cm.exception))

	def test_unknown_access_preview_timeout(self):
		roles = [
			Role('role1', role_path="/", trust_policy=copy.deepcopy(trust_policy_with_no_findings))
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
				validator.validate_roles(roles)

			self.assertEqual('Timed out after 5 minutes waiting for access analyzer preview to create.', str(cm.exception))

	def test_if_no_analyzer_exists_in_account(self):
		validator = Validator(account_config.account_id, account_config.region, account_config.partition)
		with Stubber(validator.client) as stubber:
			stubber.add_response('list_analyzers', {'analyzers': []}, {'type': 'ACCOUNT'})
			stubber.add_response('create_analyzer',
								{'arn': 'arn:aws:access-analyzer:us-east-1:123456789123:analyzer/MyAnalyzer'},
								{'analyzerName': validator.access_analyzer_name, 'type': 'ACCOUNT'})
			validator.validate_roles([])
			stubber.assert_no_pending_responses()
