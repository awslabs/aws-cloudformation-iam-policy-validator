"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import json
import os
import unittest

from cfn_policy_validator.tests import account_config, offline_only
from cfn_policy_validator.tests.validation_tests import MockNoFindings, \
	mock_access_analyzer_identity_setup, FINDING_TYPE, MockValidateIdentityPolicyFinding
from cfn_policy_validator.validation.validator import validate_parser_output
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.output import Output, Policy, User, Group, PermissionSet

policy_document_with_no_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': 'iam:ListRoles',
			'Resource': '*'
		}
	]
}


policy_document_with_findings = {
	'Version': '2012-10-17',
	'Statement': [
		{
			'Effect': 'Allow',
			'Action': 'iam:PassRole',
			'Resource': '*'
		}
	]
}

invalid_policy_document = {
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

this_files_directory = os.path.dirname(os.path.realpath(__file__))


class WhenValidatingPolicies(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	@mock_access_analyzer_identity_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_does_not_add_identity_finding_for_good_policies(self):
		self.output.OrphanedPolicies = [
			Policy('Policy1', copy.deepcopy(policy_document_with_no_findings), 'MyPath'),
			Policy('Policy2', copy.deepcopy(policy_document_with_no_findings))
		]

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING)
	)
	def test_adds_identity_finding_for_bad_policies(self):
		self.output.OrphanedPolicies = [
			Policy('Policy1', copy.deepcopy(policy_document_with_findings), 'MyPath'),
			Policy('Policy2', copy.deepcopy(policy_document_with_findings))
		]

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.security_warnings[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('No resource attached', first_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', first_finding.code)

		second_finding = findings.security_warnings[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('No resource attached', second_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', second_finding.code)

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR),
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR)
	)
	def test_adds_identity_finding_with_invalid_policy(self):
		self.output.OrphanedPolicies = [
			Policy('Policy1', copy.deepcopy(invalid_policy_document), 'MyPath'),
			Policy('Policy2', copy.deepcopy(invalid_policy_document))
		]

		findings = validate_parser_output(self.output)
		self.assertEqual(2, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.errors[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('No resource attached', first_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', first_finding.code)

		second_finding = findings.errors[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('No resource attached', second_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', second_finding.code)


class WhenValidatingUsers(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	def add_users_to_output(self, policy_document):
		user1 = User('user1', user_path='/')
		user1.add_policy(Policy('Policy1', copy.deepcopy(policy_document)))

		user2 = User('user2', user_path='/')
		user2.add_policy(Policy('Policy2', copy.deepcopy(policy_document)))

		self.output.Users = [
			user1,
			user2
		]

	@mock_access_analyzer_identity_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_does_not_add_identity_finding_for_good_policies(self):
		self.add_users_to_output(policy_document_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING)
	)
	def test_adds_identity_finding_for_bad_policies(self):
		self.add_users_to_output(policy_document_with_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.security_warnings[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('user1', first_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', first_finding.code)

		second_finding = findings.security_warnings[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('user2', second_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', second_finding.code)

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR),
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR)
	)
	def test_adds_identity_finding_with_invalid_policy(self):
		self.add_users_to_output(invalid_policy_document)

		findings = validate_parser_output(self.output)
		self.assertEqual(2, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.errors[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('user1', first_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', first_finding.code)

		second_finding = findings.errors[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('user2', second_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', second_finding.code)


class WhenValidatingGroups(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	def add_groups_to_output(self, policy_document):
		group1 = Group('group1', group_path='/')
		group1.add_policy(Policy('Policy1', copy.deepcopy(policy_document)))

		group2 = Group('group2', group_path='/')
		group2.add_policy(Policy('Policy2', copy.deepcopy(policy_document)))

		self.output.Groups = [
			group1,
			group2
		]

	@mock_access_analyzer_identity_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_does_not_add_identity_finding_for_good_policies(self):
		self.add_groups_to_output(policy_document_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING)
	)
	def test_adds_identity_finding_for_bad_policies(self):
		self.add_groups_to_output(policy_document_with_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.security_warnings[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('group1', first_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', first_finding.code)

		second_finding = findings.security_warnings[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('group2', second_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', second_finding.code)

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR),
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR)
	)
	def test_adds_identity_finding_with_invalid_policy(self):
		self.add_groups_to_output(invalid_policy_document)

		findings = validate_parser_output(self.output)
		self.assertEqual(2, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.errors[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('group1', first_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', first_finding.code)

		second_finding = findings.errors[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('group2', second_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', second_finding.code)


class WhenValidatingPermissionSets(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	def add_permission_sets_to_output(self, policy_document):
		permission_set = PermissionSet('permission_set1')
		permission_set.add_policy(Policy('Policy1', copy.deepcopy(policy_document)))

		permission_set2 = PermissionSet('permission_set2')
		permission_set2.add_policy(Policy('Policy2', copy.deepcopy(policy_document)))

		self.output.PermissionSets = [
			permission_set,
			permission_set2
		]

	@mock_access_analyzer_identity_setup(
		MockNoFindings(),
		MockNoFindings()
	)
	def test_does_not_add_identity_finding_for_good_policies(self):
		self.add_permission_sets_to_output(policy_document_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING)
	)
	def test_adds_identity_finding_for_bad_policies(self):
		self.add_permission_sets_to_output(policy_document_with_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.security_warnings[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('permission_set1', first_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', first_finding.code)

		second_finding = findings.security_warnings[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('permission_set2', second_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', second_finding.code)

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR),
		MockValidateIdentityPolicyFinding(code='DATA_TYPE_MISMATCH', finding_type=FINDING_TYPE.ERROR)
	)
	def test_adds_identity_finding_with_invalid_policy(self):
		self.add_permission_sets_to_output(invalid_policy_document)

		findings = validate_parser_output(self.output)
		self.assertEqual(2, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.errors[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('permission_set1', first_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', first_finding.code)

		second_finding = findings.errors[1]
		self.assertEqual('Policy2', second_finding.policyName)
		self.assertEqual('permission_set2', second_finding.resourceName)
		self.assertEqual('DATA_TYPE_MISMATCH', second_finding.code)


def load_file_with_max_size_policy(file_name):
	with open(os.path.join(this_files_directory, f'test_files/{file_name}'), 'r') as input_file, \
			open(os.path.join(this_files_directory, 'test_files/policy_that_exceeds_max_size.json'), 'r') as max_size_policy:
		input_file = input_file.read()
		max_size_policy = max_size_policy.read()
		input_file = input_file.replace("{{max_size_policy}}", max_size_policy)
		return json.loads(input_file)


class WhenValidatingPoliciesAndPolicyExceedsMaximumValidatePolicySize(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	def add_policies_to_output(self, policy_document):
		policy1 = Policy('Policy1', copy.deepcopy(policy_document))

		self.output.OrphanedPolicies = [
			policy1
		]

	@mock_access_analyzer_identity_setup()
	def test_returns_error_finding(self):
		input_file = load_file_with_max_size_policy('input_with_max_size_policy.json')
		self.add_policies_to_output(input_file)

		findings = validate_parser_output(self.output)
		self.assertEqual(1, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.errors[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('No resource attached', first_finding.resourceName)
		self.assertEqual('POLICY_SIZE_EXCEEDS_VALIDATE_POLICY_MAXIMUM', first_finding.code)


class WhenValidatingPoliciesAndPolicyExceedsMaximumValidatePolicySizeAndIsAWSManagedPolicy(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

	def add_policies_to_output(self, policy_document):
		policy1 = Policy('Policy1', copy.deepcopy(policy_document), is_aws_managed_policy=True)

		self.output.OrphanedPolicies = [
			policy1
		]

	@mock_access_analyzer_identity_setup()
	def test_ignores_max_size(self):
		input_file = load_file_with_max_size_policy('input_with_max_size_policy.json')
		self.add_policies_to_output(input_file)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))


class WhenValidatingPoliciesAndFindingsPaginate(unittest.TestCase):
	def setUp(self):
		self.output = Output(account_config)

	@mock_access_analyzer_identity_setup(
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING, has_next_token_in_response=True),
		MockValidateIdentityPolicyFinding(code='PASS_ROLE_WITH_STAR_IN_RESOURCE', finding_type=FINDING_TYPE.SECURITY_WARNING, has_next_token_in_request=True),

		MockValidateIdentityPolicyFinding(code='ANOTHER_SECURITY_WARNING', finding_type=FINDING_TYPE.SECURITY_WARNING, has_next_token_in_response=True),
		MockValidateIdentityPolicyFinding(code='ANOTHER_SECURITY_WARNING', finding_type=FINDING_TYPE.SECURITY_WARNING, has_next_token_in_request=True)
	)
	@offline_only
	def test_adds_identity_finding_for_bad_policies(self):
		self.output.OrphanedPolicies = [
			Policy('Policy1', copy.deepcopy(policy_document_with_findings), 'MyPath'),
			Policy('Policy2', copy.deepcopy(policy_document_with_findings))
		]

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(4, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

		first_finding = findings.security_warnings[0]
		self.assertEqual('Policy1', first_finding.policyName)
		self.assertEqual('No resource attached', first_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', first_finding.code)

		second_finding = findings.security_warnings[1]
		self.assertEqual('Policy1', second_finding.policyName)
		self.assertEqual('No resource attached', second_finding.resourceName)
		self.assertEqual('PASS_ROLE_WITH_STAR_IN_RESOURCE', second_finding.code)

		third_finding = findings.security_warnings[2]
		self.assertEqual('Policy2', third_finding.policyName)
		self.assertEqual('No resource attached', third_finding.resourceName)
		self.assertEqual('ANOTHER_SECURITY_WARNING', third_finding.code)

		fourth_finding = findings.security_warnings[3]
		self.assertEqual('Policy2', fourth_finding.policyName)
		self.assertEqual('No resource attached', fourth_finding.resourceName)
		self.assertEqual('ANOTHER_SECURITY_WARNING', fourth_finding.code)
