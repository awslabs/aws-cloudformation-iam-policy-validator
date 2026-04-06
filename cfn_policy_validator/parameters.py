"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json

from json import JSONDecodeError

from argparse import ArgumentTypeError
from botocore.config import Config
from botocore.exceptions import InvalidRegionError
from botocore.utils import validate_region_name

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError


def merge(parameters, template_configuration_file_path):
	"""
	Merge parameters passed in via the parameters argument with parameters from the template configuration file.
	"""

	parameters_from_config_file = {}
	if template_configuration_file_path is not None:
		parameters_from_config_file = _read_parameters_from_file(template_configuration_file_path)

	if parameters is None:
		parameters = {}

	# parameters passed on the command line take precedence over those in the configuration file
	# this is because the command line will typically be more controlled / trusted than the config file
	parameters_from_config_file.update(parameters)

	return parameters_from_config_file


def _read_parameters_from_file(file_path):
	"""
	Read parameters from a configuration file. Supports multiple formats:

	1. CodePipeline template configuration file (existing format):
	   {"Parameters": {"Key1": "Value1", "Key2": "Value2"}}

	2. CloudFormation-style parameter list:
	   [{"ParameterKey": "Key1", "ParameterValue": "Value1"}, ...]

	3. Key=Value string list (as used by AWS CLI deploy --parameter-overrides):
	   ["Key1=Value1", "Key2=Value2"]
	"""
	parsed = _read_json_file(file_path)
	return _normalize_parameters(parsed)


def _read_json_file(file_path):
	try:
		with open(file_path, 'r') as stream:
			raw_file = stream.read()
			return json.loads(raw_file)
	except FileNotFoundError:
		raise ApplicationError(f'Template configuration file not found: {file_path}')
	except JSONDecodeError:
		raise ApplicationError(f'Template configuration file contains invalid json: {file_path}')


def _normalize_parameters(parsed):
	"""
	Detect the format of the parsed JSON and normalize to a flat {key: value} dict.
	"""

	# Format 1: CodePipeline template configuration file - {"Parameters": {"Key": "Value"}}
	if isinstance(parsed, dict):
		parameters = parsed.get('Parameters', {})
		if not isinstance(parameters, dict):
			raise ApplicationError(
				'The value for "Parameters" in the template configuration file must be a JSON object.\n'
				'See CloudFormation documentation on format for this file: '
				'"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15"'
			)
		return parameters

	# Format 2 & 3: JSON array
	if isinstance(parsed, list):
		if len(parsed) == 0:
			return {}

		first = parsed[0]

		# Format 2: CloudFormation-style [{"ParameterKey": "Key1", "ParameterValue": "Value1"}, ...]
		if isinstance(first, dict):
			return _parse_cfn_style_parameters(parsed)

		# Format 3: Key=Value string list ["Key1=Value1", "Key2=Value2"]
		if isinstance(first, str):
			return _parse_key_value_string_parameters(parsed)

	raise ApplicationError(
		'Unsupported parameter file format. Supported formats:\n'
		'  - CodePipeline configuration: {"Parameters": {"Key": "Value"}}\n'
		'  - CloudFormation-style list:  [{"ParameterKey": "Key", "ParameterValue": "Value"}, ...]\n'
		'  - Key=Value string list:      ["Key1=Value1", "Key2=Value2"]'
	)


def _parse_cfn_style_parameters(parameter_list):
	"""Parse [{"ParameterKey": "K", "ParameterValue": "V"}, ...] into {K: V}."""
	result = {}
	for item in parameter_list:
		if not isinstance(item, dict):
			raise ApplicationError(
				f'Expected a JSON object with "ParameterKey" and "ParameterValue" but got: {item}'
			)
		if 'ParameterKey' not in item or 'ParameterValue' not in item:
			raise ApplicationError(
				f'Each parameter object must contain "ParameterKey" and "ParameterValue". Got: {json.dumps(item)}'
			)
		result[item['ParameterKey']] = item['ParameterValue']
	return result


def _parse_key_value_string_parameters(parameter_list):
	"""Parse ["Key1=Value1", "Key2=Value2"] into {Key1: Value1}."""
	result = {}
	for item in parameter_list:
		if not isinstance(item, str) or '=' not in item:
			raise ApplicationError(
				f'Expected a parameter string in the format "Key=Value" but got: {item}'
			)
		key, value = item.split('=', 1)
		result[key] = value
	return result


def validate_region(region):
	try:
		# this call validates that the region name is valid, but does not validate that the region actually exists
		validate_region_name(region)
	except InvalidRegionError:
		raise ArgumentTypeError(f'Invalid region name: {region}.')

	return region


def validate_credentials(region):
	# run a test to validate the provided credentials
	# create our own config here to control retries and fail fast if credentials are invalid
	sts_client = client.build('sts', region, client_config=Config(retries={'mode': 'standard', 'max_attempts': 2}))
	sts_client.get_caller_identity()


def validate_finding_types_from_cli(value):
	"""
	Validate that the finding types provided are valid finding types.
	"""

	finding_types = value.split(',')
	finding_types = validate_finding_types(finding_types)

	return finding_types


def validate_finding_types(finding_types):
	if finding_types is None:
		return finding_types

	finding_types = [finding_type.strip() for finding_type in finding_types]
	finding_types = [finding_type.upper() for finding_type in finding_types]

	for finding_type in finding_types:
		if finding_type not in ['ERROR', 'SECURITY_WARNING', 'SUGGESTION', 'WARNING', 'NONE']:
			raise ArgumentTypeError(f"Invalid finding type: {finding_type}.")

	return finding_types
