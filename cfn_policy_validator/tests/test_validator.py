"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from unittest.mock import patch

from cfn_policy_validator import main as main_module
from cfn_policy_validator.main import main
from cfn_policy_validator.tests import mock_validation_setup
from cfn_policy_validator.tests.boto_mocks import BotoClientError
from cfn_policy_validator.tests.utils import captured_output, ignore_warnings


def build_valid_args(path='abcdef', region='us-east-1'):
	return [
		'validate',
		'--template-path', path,
		'--region', region
	]


class ValidationTest(unittest.TestCase):
	def setUp(self):
		ignore_warnings()

	def assert_parameter_validation_failed(self, args, error_message):
		with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
			main(args)

		self.assertEqual(2, context_manager.exception.code)
		self.assertIn(error_message, err.getvalue())

	@staticmethod
	def assert_valid_parameter(args):
		with patch.object(main_module, 'validate_from_cli') as mock:
			main(args)
			mock.assert_called_once()


class WhenValidatingRegion(ValidationTest):
	def assert_validation_fails(self, args):
		self.assert_parameter_validation_failed(args, "Invalid region name.")

	@mock_validation_setup()
	def test_with_invalid_region_name(self):
		args = build_valid_args(region='us-!est-2')
		self.assert_parameter_validation_failed(args, "Invalid region name: us-!est-2.")

	@mock_validation_setup(
		sts=[
			BotoClientError(
				method='get_caller_identity',
				service_error_code='EndpointConnectionError',
				service_message='Could not connect to the endpoint URL: "https://sts.us-qwest-1.amazonaws.com/"'
			)
		]
	)
	def test_with_invalid_region(self):
		args = build_valid_args(region='us-qwest-1')

		with self.assertRaises(SystemExit) as context_manager, captured_output() as (out, err):
			main(args)

		self.assertEqual(1, context_manager.exception.code)
		self.assertIn("Could not connect to the endpoint URL: \"https://sts.us-qwest-1.amazonaws.com/\"", err.getvalue())

	@mock_validation_setup()
	def test_with_valid_region(self):
		args = build_valid_args(region='us-west-2')
		self.assert_valid_parameter(args)


class WhenValidatingTreatAsBlocking(ValidationTest):
	def setUp(self):
		self.args = build_valid_args()

	def assert_validation_fails(self, value='INVALID'):
		self.assert_parameter_validation_failed(self.args, f'Invalid finding type: {value}')

	@mock_validation_setup()
	def test_with_invalid_value(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'INVALID'])
		self.assert_validation_fails()

	@mock_validation_setup()
	def test_with_one_valid_and_one_invalid_value(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'INVALID,WARNING'])
		self.assert_validation_fails()

	@mock_validation_setup()
	def test_with_two_valid_values(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'WARNING,ERROR'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_warning(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'WARNING'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_error(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'ERROR'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_suggestion(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'SUGGESTION'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_security_warning(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'SECURITY_WARNING'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_none(self):
		self.args.extend(['--treat-finding-type-as-blocking', 'NONE'])
		self.assert_valid_parameter(self.args)

	@mock_validation_setup()
	def test_with_no_value(self):
		self.args.extend(['--treat-finding-type-as-blocking', ''])
		self.assert_validation_fails(value='')
