"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from botocore.exceptions import ClientError

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.regex_patterns import dynamic_ssm_reference_regex


class DynamicReferenceEvaluator:
	def __init__(self, region):
		self.ssm_client = client.build('ssm', region)

	def evaluate(self, value):
		dynamic_ssm_references = dynamic_ssm_reference_regex.findall(value)
		for dynamic_ssm_reference in dynamic_ssm_references:
			dynamic_reference_text = dynamic_ssm_reference[0]
			parameter_name = dynamic_ssm_reference[1]
			parameter_version = dynamic_ssm_reference[2]

			if parameter_version == '':
				raise ApplicationError('Dynamic references to SSM parameters must include a version number to ensure the'
									   ' value does not change between validation and deployment.  Invalid dynamic '
									   f'reference: {dynamic_reference_text}')

			parameter_with_version = f'{parameter_name}:{parameter_version}'

			try:
				response = self.ssm_client.get_parameter(
					Name=parameter_with_version
				)
			except ClientError as e:
				if e.response['Error']['Code'] == 'ParameterNotFound':
					raise ApplicationError(f'Could not find SSM parameter referenced by dynamic reference: {dynamic_reference_text}')
				if e.response['Error']['Code'] == 'ParameterVersionNotFound':
					raise ApplicationError(f'Could not find version {parameter_version} of SSM parameter referenced by dynamic reference: {dynamic_reference_text}')
				raise

			value = value.replace(dynamic_ssm_reference[0], response['Parameter']['Value'])

		return value
