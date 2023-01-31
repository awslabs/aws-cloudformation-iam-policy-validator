"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.regex_patterns import dynamic_ssm_reference_regex
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests import offline_only
from cfn_policy_validator.tests.boto_mocks import BotoResponse, BotoClientError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load_resources, account_config, load, default_get_latest_ssm_parameter_version


class WhenEvaluatingPolicyWithDynamicReference(unittest.TestCase):
	@mock_node_evaluator_setup(
		ssm=[
			BotoResponse(
				method='get_parameter',
				service_response={
					'Parameter': {
						'Version': 1,
						'Value': 'Version1'
					}
				},
				expected_params={
					'Name': '/my/parameter1:1'
				}
			)
		]
	)
	@offline_only
	def test_simple_reference(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm:/my/parameter1:1}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})
		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'Version1')

	@mock_node_evaluator_setup(
		ssm=[
			BotoResponse(
				method='get_parameter',
				service_response={
					'Parameter': {
						'Version': 1,
						'Value': 'Parameter2Version1'
					}
				},
				expected_params={
					'Name': '/my/parameter2:1'
				}
			),
			BotoResponse(
				method='get_parameter',
				service_response={
					'Parameter': {
						'Version': 1,
						'Value': 'Parameter1Version1'
					}
				},
				expected_params={
					'Name': '/my/parameter1:1'
				}
			)
		]
	)
	@offline_only
	def test_multiple_dynamic_references_in_single_string(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm:/my/parameter2:1}}-{{resolve:ssm:/my/parameter1:1}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})
		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'Parameter2Version1-Parameter1Version1')

	@mock_node_evaluator_setup()
	def test_dynamic_reference_with_no_version(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm:MyParameter}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('Dynamic references to SSM parameters must include a version number to ensure the'
						 ' value does not change between validation and deployment. Invalid dynamic '
						 'reference: {{resolve:ssm:MyParameter}}. This can be disabled using the'
						 '--retrieve-latest-ssm-parameter-versions flag',
						 str(cm.exception))

	@mock_node_evaluator_setup(
		ssm=[
			BotoResponse(
				method='get_parameter',
				service_response={
					'Parameter': {
						'Version': 1,
						'Value': 'Version1'
					}
				},
				expected_params={
					'Name': '/my/param1:1'
				}
			)
		]
	)
	@offline_only
	def test_nested_reference(self):
		template = load({
			'Parameters': {
				'MyParameter': {
					'Type': 'String'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Join': [
								'',
								[
									'{{',
									'resolve:ss',
									'm:',
									{'Ref': 'MyParameter'},
									'}}'
								]
							]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {
			'MyParameter': '/my/param1:1'
		})
		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'Version1')

	@mock_node_evaluator_setup(
		ssm=[
			BotoClientError(
				method='get_parameter',
				service_error_code='ParameterVersionNotFound',
				expected_params={
					'Name': '/my/parameter:3'
				}
			)
		]
	)
	@offline_only
	def test_no_parameter_with_version_exists(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm:/my/parameter:3}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual('Could not find version 3 of SSM parameter referenced by dynamic reference: {{resolve:ssm:/my/parameter:3}}',
						 str(cm.exception))


	@mock_node_evaluator_setup(
		ssm=[
			BotoClientError(
				method='get_parameter',
				service_error_code='ParameterNotFound',
				expected_params={
					'Name': '/my/parameter:3'
				}
			)
		]
	)
	def test_no_parameter_with_name_exists(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm:/my/parameter:3}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(
			'Could not find SSM parameter referenced by dynamic reference: {{resolve:ssm:/my/parameter:3}}',
			str(cm.exception))


class WhenEvaluatingDynamicSSMReferenceRegex(unittest.TestCase):
	def test_matches_simple_example(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:MyParameter:1}}')
		self.assertEqual('MyParameter', match.group(2))
		self.assertEqual('1', match.group(3))

	def test_matches_with_forward_slashes(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:/my/parameter/:100}}')
		self.assertEqual('/my/parameter/', match.group(2))
		self.assertEqual('100', match.group(3))

	def test_matches_no_version(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:/my/parameter/}}')
		self.assertEqual('/my/parameter/', match.group(2))
		self.assertEqual(None, match.group(3))

	def test_does_not_match_missing_end_brackets(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:/my/parameter/')
		self.assertIsNone(match)

	def test_does_not_match_missing_start_brackets(self):
		match = dynamic_ssm_reference_regex.match('resolve:ssm:/my/parameter/}}')
		self.assertIsNone(match)

	def test_does_not_match_missing_resolve(self):
		match = dynamic_ssm_reference_regex.match('{{:ssm:/my/parameter/}}')
		self.assertIsNone(match)

	def test_does_not_match_ssm_secure(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm-secure:/my/parameter/}}')
		self.assertIsNone(match)

	def test_does_not_match_missing_param_name_with_version(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm::1}}')
		self.assertIsNone(match)

	def test_does_not_match_missing_param_name_without_version(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:}}')
		self.assertIsNone(match)

	def test_does_not_match_non_integer_version_number(self):
		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:param:a}}')
		self.assertIsNone(match)

		match = dynamic_ssm_reference_regex.match('{{resolve:ssm:param:!}}')
		self.assertIsNone(match)

	def test_matches_multiple_references(self):
		match = dynamic_ssm_reference_regex.findall('{{resolve:ssm:param:1}}::{{resolve:ssm:param:2}}')
		self.assertEqual(2, len(match))


class WhenEvaluatingPolicyWithSsmSecureDynamicReference(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_dynamic_reference_is_ignored(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:ssm-secure:/my/parameter1:1}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, '{{resolve:ssm-secure:/my/parameter1:1}}')


class WhenEvaluatingPolicyWithSecretDynamicReference(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_dynamic_reference_is_ignored(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': '{{resolve:secretsmanager:/my/parameter1:1}}'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, default_get_latest_ssm_parameter_version, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, '{{resolve:secretsmanager:/my/parameter1:1}}')
