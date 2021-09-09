"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import jsonschema

from jsonschema import ValidationError
from cfn_policy_validator.application_error import SchemaValidationError

alphanumeric_regex = '^[a-zA-Z0-9]+$'


def validate(template):
	# this schema validates that the CloudFormation template has a valid Resources, Parameters, and Mappings section.
	# validating upfront allows us to make assumptions later that we're dealing with a valid template
	template_schema = {
		'type': 'object',
		'properties': {
			'Resources': {
				'type': 'object',
				'patternProperties': {
					alphanumeric_regex: {
						'type': 'object',
						'properties': {
							'Type': {
								'type': 'string'
							},
							'Properties': {
								'type': 'object'
							}
						},
						'required': ['Type']
					}
				},
				'additionalProperties': False
			},
			'Parameters': {
				'type': 'object',
				'additionalProperties': {
					'type': 'object'
				}
			},
			'Mappings': {
				'type': 'object',
				'patternProperties': {
					alphanumeric_regex: {
						'type': 'object',
						'patternProperties': {
							'^.*$': {
								'type': 'object',
								'patternProperties': {
									'^.*$': {
										'type': ['string', 'array'],
										'minProperties': 1
									}
								},
								'minProperties': 1,
								'additionalProperties': False
							}
						},
						'minProperties': 1,
						'additionalProperties': False
					}
				},
				'additionalProperties': False
			}
		},
		'required': ['Resources']
	}

	validate_schema(template, template_schema)


def validate_schema(instance, schema, parent_path=None):
	try:
		jsonschema.validate(instance=instance, schema=schema)
	except ValidationError as e:
		message = e.message

		# try to print a useful error message about where the validation issue is in the template
		path = ''
		if e.path:
			path = e.path.popleft()
			for item in e.path:
				# items can be integers or strings
				path = f'{path}.{item}'

		if parent_path is not None:
			path = parent_path if path == '' else f'{parent_path}.{path}'

		if path:
			raise SchemaValidationError(f'{message}, Path: {path}')

		raise SchemaValidationError(f'{message}')
