"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.validation.validator import validate_parser_output
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.output import Output, Policy, User, Group

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


class WhenValidatingPolicies(unittest.TestCase):
	def setUp(self):
		account_config = AccountConfig('aws', 'us-east-1', '123456789123')
		self.output = Output(account_config)

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

	def test_does_not_add_identity_finding_for_good_policies(self):
		self.add_users_to_output(policy_document_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

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

	def test_does_not_add_identity_finding_for_good_policies(self):
		self.add_groups_to_output(policy_document_with_no_findings)

		findings = validate_parser_output(self.output)
		self.assertEqual(0, len(findings.errors))
		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))

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
