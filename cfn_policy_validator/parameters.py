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

	template_configuration_file = {}
	if template_configuration_file_path is not None:
		template_configuration_file = _read_template_configuration_file(template_configuration_file_path)

	parameters_from_config_file = template_configuration_file.get('Parameters', {})
	if not isinstance(parameters_from_config_file, dict):
		raise ApplicationError(f'The value for "Parameters" in the template configuration value must be a JSON object.\n'
								'See CloudFormation documentation on format for this file: '
								'"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/continuous-delivery-codepipeline-cfn-artifacts.html#w2ab1c21c15c15"')

	if parameters is None:
		parameters = {}

	# parameters passed on the command line take precedence over those in the configuration file
	# this is because the command line will typically be more controlled / trusted than the config file
	parameters_from_config_file.update(parameters)

	return parameters_from_config_file


def _read_template_configuration_file(template_configuration_file_path):
	try:
		with open(template_configuration_file_path, 'r') as stream:
			raw_file = stream.read()
			return json.loads(raw_file)
	except FileNotFoundError:
		raise ApplicationError(f'Template configuration file not found: {template_configuration_file_path}')
	except JSONDecodeError:
		raise ApplicationError(f'Template configuration file contains invalid json: {template_configuration_file_path}')


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
