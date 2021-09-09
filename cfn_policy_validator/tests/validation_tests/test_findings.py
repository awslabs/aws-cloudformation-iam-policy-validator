"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.validation.findings import Findings


class WhenAddingTrustPolicyFindings(unittest.TestCase):
	def test_add_trust_policy_finding(self):
		findings = Findings()

		fields = {
			'field1': 'MyField1',
			'field2': 'MyField2'
		}

		access_analyzer_findings = [
			fields,
			fields
		]

		resource_name = 'resource'
		findings.add_trust_policy_finding(access_analyzer_findings, resource_name)

		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))
		self.assertEqual(0, len(findings.errors))

		expected_message = 'Trust policy allows access from external principals.'
		expected_policy_name = 'TrustPolicy'
		first_finding = findings.security_warnings[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(expected_policy_name, first_finding.policyName)
		self.assertEqual('SECURITY_WARNING', first_finding.findingType)
		self.assertEqual(expected_message, first_finding.message)
		self.assertEqual('EXTERNAL_PRINCIPAL', first_finding.code)
		self.assertEqual(access_analyzer_findings[0], first_finding.details)

		second_finding = findings.security_warnings[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(expected_policy_name, second_finding.policyName)
		self.assertEqual('SECURITY_WARNING', second_finding.findingType)
		self.assertEqual(expected_message, second_finding.message)
		self.assertEqual('EXTERNAL_PRINCIPAL', second_finding.code)
		self.assertEqual(access_analyzer_findings[1], second_finding.details)


class WhenAddingIdentityFindings(unittest.TestCase):
	def test_add_identity_finding_error(self):
		findings = Findings()

		resource_name = 'TestResource'
		policy_name = 'TestPolicy'
		message1 = 'this is a policy message 1'
		message2 = 'this is a policy message 2'
		issue_code1 = 'issue 1'
		issue_code2 = 'issue 2'

		access_analyzer_findings = [
			{'findingType': 'ERROR', 'findingDetails': message1, 'issueCode': issue_code1},
			{'findingType': 'ERROR', 'findingDetails': message2, 'issueCode': issue_code2}
		]

		findings.add_validation_finding(
			findings=access_analyzer_findings,
			resource_name=resource_name,
			policy_name=policy_name
		)

		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))
		self.assertEqual(2, len(findings.errors))

		first_finding = findings.errors[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(policy_name, first_finding.policyName)
		self.assertEqual('ERROR', first_finding.findingType)
		self.assertEqual(message1, first_finding.message)
		self.assertEqual(issue_code1, first_finding.code)
		self.assertEqual(access_analyzer_findings[0], first_finding.details)

		second_finding = findings.errors[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(policy_name, second_finding.policyName)
		self.assertEqual('ERROR', second_finding.findingType)
		self.assertEqual(message2, second_finding.message)
		self.assertEqual(issue_code2, second_finding.code)
		self.assertEqual(access_analyzer_findings[1], second_finding.details)

	def test_add_identity_finding_security_warning(self):
		findings = Findings()

		resource_name = 'TestResource'
		policy_name = 'TestPolicy'
		message1 = 'this is a policy message 1'
		message2 = 'this is a policy message 2'
		issue_code1 = 'issue 1'
		issue_code2 = 'issue 2'

		access_analyzer_findings = [
			{'findingType': 'SECURITY_WARNING', 'findingDetails': message1, 'issueCode': issue_code1},
			{'findingType': 'SECURITY_WARNING', 'findingDetails': message2, 'issueCode': issue_code2}
		]

		findings.add_validation_finding(
			findings=access_analyzer_findings,
			resource_name=resource_name,
			policy_name=policy_name
		)

		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))
		self.assertEqual(0, len(findings.errors))

		first_finding = findings.security_warnings[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(policy_name, first_finding.policyName)
		self.assertEqual('SECURITY_WARNING', first_finding.findingType)
		self.assertEqual(message1, first_finding.message)
		self.assertEqual(issue_code1, first_finding.code)
		self.assertEqual(access_analyzer_findings[0], first_finding.details)

		second_finding = findings.security_warnings[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(policy_name, second_finding.policyName)
		self.assertEqual('SECURITY_WARNING', second_finding.findingType)
		self.assertEqual(message2, second_finding.message)
		self.assertEqual(issue_code2, second_finding.code)
		self.assertEqual(access_analyzer_findings[1], second_finding.details)

	def test_add_identity_finding_suggestion(self):
		findings = Findings()

		resource_name = 'TestResource'
		policy_name = 'TestPolicy'
		message1 = 'this is a policy message 1'
		message2 = 'this is a policy message 2'
		issue_code1 = 'issue 1'
		issue_code2 = 'issue 2'

		access_analyzer_findings = [
			{'findingType': 'SUGGESTION', 'findingDetails': message1, 'issueCode': issue_code1},
			{'findingType': 'SUGGESTION', 'findingDetails': message2, 'issueCode': issue_code2}
		]

		findings.add_validation_finding(
			findings=access_analyzer_findings,
			resource_name=resource_name,
			policy_name=policy_name
		)

		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(2, len(findings.suggestions))
		self.assertEqual(0, len(findings.errors))


		first_finding = findings.suggestions[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(policy_name, first_finding.policyName)
		self.assertEqual('SUGGESTION', first_finding.findingType)
		self.assertEqual(message1, first_finding.message)
		self.assertEqual(issue_code1, first_finding.code)
		self.assertEqual(access_analyzer_findings[0], first_finding.details)

		second_finding = findings.suggestions[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(policy_name, second_finding.policyName)
		self.assertEqual('SUGGESTION', second_finding.findingType)
		self.assertEqual(message2, second_finding.message)
		self.assertEqual(issue_code2, second_finding.code)
		self.assertEqual(access_analyzer_findings[1], second_finding.details)

	def test_add_identity_finding_warning(self):
		findings = Findings()

		resource_name = 'TestResource'
		policy_name = 'TestPolicy'
		message1 = 'this is a policy message 1'
		message2 = 'this is a policy message 2'
		issue_code1 = 'issue 1'
		issue_code2 = 'issue 2'

		access_analyzer_findings = [
			{'findingType': 'WARNING', 'findingDetails': message1, 'issueCode': issue_code1},
			{'findingType': 'WARNING', 'findingDetails': message2, 'issueCode': issue_code2}
		]

		findings.add_validation_finding(
			findings=access_analyzer_findings,
			resource_name=resource_name,
			policy_name=policy_name
		)

		self.assertEqual(0, len(findings.security_warnings))
		self.assertEqual(2, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))
		self.assertEqual(0, len(findings.errors))

		first_finding = findings.warnings[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(policy_name, first_finding.policyName)
		self.assertEqual('WARNING', first_finding.findingType)
		self.assertEqual(message1, first_finding.message)
		self.assertEqual(issue_code1, first_finding.code)
		self.assertEqual(access_analyzer_findings[0], first_finding.details)

		second_finding = findings.warnings[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(policy_name, second_finding.policyName)
		self.assertEqual('WARNING', second_finding.findingType)
		self.assertEqual(message2, second_finding.message)
		self.assertEqual(issue_code2, second_finding.code)
		self.assertEqual(access_analyzer_findings[1], second_finding.details)


class WhenAddingExternalPrincipalFindings(unittest.TestCase):
	def test_add_external_principal_findings(self):
		findings = Findings()

		resource_name = 'TestResource'
		policy_name = 'TestPolicy'

		default_message = 'Resource policy allows access from external principals.'

		access_analyzer_findings = [
			{'someField': 'someValue'},
			{'someField': 'someValue2'}
		]

		expected_details = [
			{'someField': 'someValue'},
			{'someField': 'someValue2'}
		]

		findings.add_external_principal_finding(
			findings=access_analyzer_findings,
			resource_name=resource_name,
			policy_name=policy_name
		)

		self.assertEqual(2, len(findings.security_warnings))
		self.assertEqual(0, len(findings.warnings))
		self.assertEqual(0, len(findings.suggestions))
		self.assertEqual(0, len(findings.errors))

		first_finding = findings.security_warnings[0]
		self.assertEqual(resource_name, first_finding.resourceName)
		self.assertEqual(policy_name, first_finding.policyName)
		self.assertEqual('SECURITY_WARNING', first_finding.findingType)
		self.assertEqual(default_message, first_finding.message)
		self.assertEqual('EXTERNAL_PRINCIPAL', first_finding.code)
		self.assertEqual(expected_details[0], first_finding.details)

		second_finding = findings.security_warnings[1]
		self.assertEqual(resource_name, second_finding.resourceName)
		self.assertEqual(policy_name, second_finding.policyName)
		self.assertEqual('SECURITY_WARNING', second_finding.findingType)
		self.assertEqual(default_message, second_finding.message)
		self.assertEqual('EXTERNAL_PRINCIPAL', second_finding.code)
		self.assertEqual(expected_details[1], second_finding.details)
