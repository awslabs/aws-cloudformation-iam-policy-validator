"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.validation.findings import Findings, Finding
from cfn_policy_validator.validation.reporter import Reporter, default_finding_types_that_are_blocking, \
	ResourceAndCodeFindingToIgnore, ResourceOrCodeFindingToIgnore, AllowedExternalPrincipal, AllowedExternalArn


class WhenBuildingValidationReport(unittest.TestCase):
	def setUp(self):
		self.reporter = Reporter(None, default_finding_types_that_are_blocking, None)
		self.findings = Findings()

	@staticmethod
	def build_sample_finding(finding_type='ERROR'):
		return Finding("example", finding_type, "policy", "resource", {"detail": "detail"}, "code")

	def test_errors_are_classified_as_blocking_by_default(self):
		sample_finding = self.build_sample_finding()
		self.findings.errors.append(sample_finding)

		report = self.reporter.build_report_from(self.findings)

		self.assertTrue(report.has_blocking_findings(), "Report should have blocking findings")
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(sample_finding, report.blocking_findings[0])

	def test_security_warnings_are_classified_as_errors_by_default(self):
		sample_finding = self.build_sample_finding('SECURITY_WARNING')
		self.findings.security_warnings.append(sample_finding)

		report = self.reporter.build_report_from(self.findings)

		self.assertTrue(report.has_blocking_findings(), "Report should have blocking findings")
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(sample_finding, report.blocking_findings[0])

	def test_warnings_are_classified_as_warnings_by_default(self):
		sample_finding = self.build_sample_finding('WARNING')
		self.findings.warnings.append(sample_finding)

		report = self.reporter.build_report_from(self.findings)

		self.assertFalse(report.has_blocking_findings(), "Report should not have blocking findings")
		self.assertEqual(1, len(report.nonblocking_findings))
		self.assertEqual(0, len(report.blocking_findings))
		self.assertEqual(sample_finding, report.nonblocking_findings[0])

	def test_suggestions_are_classified_as_warnings_by_default(self):
		sample_finding = self.build_sample_finding('SUGGESTION')
		self.findings.suggestions.append(sample_finding)

		report = self.reporter.build_report_from(self.findings)

		self.assertFalse(report.has_blocking_findings(), "Report should not have blocking findings")
		self.assertEqual(1, len(report.nonblocking_findings))
		self.assertEqual(0, len(report.blocking_findings))
		self.assertEqual(sample_finding, report.nonblocking_findings[0])

	def test_no_values_treated_as_errors(self):
		sample_finding_1 = self.build_sample_finding('SUGGESTION')
		sample_finding_2 = self.build_sample_finding('WARNING')
		self.findings.suggestions.append(sample_finding_1)
		self.findings.warnings.append(sample_finding_2)

		self.reporter = Reporter(None, ['ERROR'], None)
		report = self.reporter.build_report_from(self.findings)

		self.assertFalse(report.has_blocking_findings(), "Report should not have blocking findings")
		self.assertEqual(2, len(report.nonblocking_findings))
		self.assertEqual(0, len(report.blocking_findings))
		self.assertIn(sample_finding_1, report.nonblocking_findings)
		self.assertIn(sample_finding_2, report.nonblocking_findings)

	def test_all_values_treated_as_blocking(self):
		sample_finding_1 = self.build_sample_finding('SUGGESTION')
		sample_finding_2 = self.build_sample_finding('WARNING')
		self.findings.suggestions.append(sample_finding_1)
		self.findings.warnings.append(sample_finding_2)

		self.reporter = Reporter(None, ['SUGGESTION', 'WARNING'], None)
		report = self.reporter.build_report_from(self.findings)

		self.assertTrue(report.has_blocking_findings(), "Report should have blocking findings")
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(2, len(report.blocking_findings))
		self.assertIn(sample_finding_1, report.blocking_findings)
		self.assertIn(sample_finding_2, report.blocking_findings)

	def test_treat_as_blocking_is_none(self):
		sample_finding_1 = self.build_sample_finding('ERROR')
		sample_finding_2 = self.build_sample_finding('WARNING')
		self.findings.errors.append(sample_finding_1)
		self.findings.warnings.append(sample_finding_2)

		self.reporter = Reporter(None, ['NONE'], None)
		report = self.reporter.build_report_from(self.findings)

		self.assertFalse(report.has_blocking_findings(), "Report should not have blocking findings")
		self.assertEqual(2, len(report.nonblocking_findings))
		self.assertEqual(0, len(report.blocking_findings))
		self.assertIn(sample_finding_1, report.nonblocking_findings)
		self.assertIn(sample_finding_2, report.nonblocking_findings)

	def test_treat_as_blocking_contains_none(self):
		sample_finding_1 = self.build_sample_finding('ERROR')
		sample_finding_2 = self.build_sample_finding('WARNING')
		self.findings.errors.append(sample_finding_1)
		self.findings.warnings.append(sample_finding_2)

		self.reporter = Reporter(None, ['NONE', 'ERROR'], None)
		report = self.reporter.build_report_from(self.findings)

		self.assertFalse(report.has_blocking_findings(), "Report should not have blocking findings")
		self.assertEqual(2, len(report.nonblocking_findings))
		self.assertEqual(0, len(report.blocking_findings))
		self.assertIn(sample_finding_1, report.nonblocking_findings)
		self.assertIn(sample_finding_2, report.nonblocking_findings)


class WhenFilteringFindingsThatWereIgnored(unittest.TestCase):
	def test_when_nothing_is_ignored(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_code_is_ignored_and_nothing_matches(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("wrong_code")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_code_is_ignored_and_something_matches(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("code")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code2")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_code_is_ignored_and_something_matches_with_different_case(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("CoDe")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code2")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_resource_is_ignored_and_nothing_matches(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("resource3")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_resource_is_ignored_and_something_matches(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("resource1")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_resource_is_ignored_and_something_matches_with_different_case(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("ReSOurCe1")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_all_findings_are_ignored(self):
		reporter = Reporter([ResourceOrCodeFindingToIgnore("code")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource2", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource3", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(0, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))

	def test_when_code_and_resource_are_ignored(self):
		reporter = Reporter([ResourceAndCodeFindingToIgnore("resource1", "code")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))

	def test_when_code_and_resource_are_ignored_with_different_cases(self):
		reporter = Reporter([ResourceAndCodeFindingToIgnore("ReSouRce1", "cOde")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))

	def test_when_code_and_resource_are_ignored_but_only_code_matches(self):
		reporter = Reporter([ResourceAndCodeFindingToIgnore("resource3", "code")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))

	def test_when_code_and_resource_are_ignored_but_only_resource_matches(self):
		reporter = Reporter([ResourceAndCodeFindingToIgnore("resource1", "code1")], default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "code")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "code")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))


class WhenFilteringFindingsForPrincipalsThatAreAllowed(unittest.TestCase):
	def test_when_nothing_is_allowed(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, None)

		finding1 = Finding("", "ERROR", "policy1", "resource1", "", "other")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", "", "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_principal_is_allowed_and_nothing_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('123456789123')])

		details = {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole'}}
		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", details, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", details, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_principal_is_allowed_and_something_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('123456789123')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': 'arn:aws:iam::123456789123:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_principal_is_account(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('123456789123')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': '123456789123'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_principal_is_federated(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('graph.facebook.com')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'Federated': 'graph.facebook.com'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_principal_is_federated_arn(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('123456789123')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'Federated': 'arn:aws:iam::123456789123:saml-provider/MyProvider'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_principal_is_star(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('*')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': '*'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_principal_is_canonical_user(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('32b753591269409b14500e0e3618a6947452385b2e16cab13d39dc097da34fa0')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1",
						   {'principal': {'CanonicalUser': '32b753591269409b14500e0e3618a6947452385b2e16cab13d39dc097da34fa0'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2",
						   {'principal': {'CanonicalUser': '42b753591269409b14500e0e3618a6947452385b2e16cab13d39dc097da34fa0'}}, "EXTERNAL_PRINCIPAL")

		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_principal_is_allowed_and_multiple_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalPrincipal('123456789123')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': '123456789123'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '123456789123'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(0, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))

	def test_when_arn_is_allowed_and_nothing_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalArn('arn:aws:iam::111222333444:role/MyOtherRole')])

		details = {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole2'}}
		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", details, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", details, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_arn_is_allowed_and_something_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalArn('arn:aws:iam::111222333444:role/MyOtherRole')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': 'arn:aws:iam::123456789123:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])

	def test_when_arn_is_allowed_and_principal_is_account(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalArn('arn:aws:iam::111222333444:role/MyOtherRole')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': '123456789123'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(2, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding1, report.blocking_findings[0])
		self.assertEqual(finding2, report.blocking_findings[1])

	def test_when_arn_is_allowed_and_principal_is_federated(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalArn('arn:aws:iam::123456789123:saml-provider/MyProvider')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'Federated': 'arn:aws:iam::123456789123:saml-provider/MyProvider'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': '111222333444'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.security_warnings.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(1, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
		self.assertEqual(finding2, report.blocking_findings[0])

	def test_when_arn_is_allowed_and_multiple_matches(self):
		reporter = Reporter(None, default_finding_types_that_are_blocking, [AllowedExternalArn('arn:aws:iam::111222333444:role/MyOtherRole')])

		finding1 = Finding("", "SECURITY_WARNING", "policy1", "resource1", {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		finding2 = Finding("", "SECURITY_WARNING", "policy1", "resource2", {'principal': {'AWS': 'arn:aws:iam::111222333444:role/MyOtherRole'}}, "EXTERNAL_PRINCIPAL")
		findings = Findings()
		findings.errors.append(finding1)
		findings.security_warnings.append(finding2)

		report = reporter.build_report_from(findings)
		self.assertEqual(0, len(report.blocking_findings))
		self.assertEqual(0, len(report.nonblocking_findings))
