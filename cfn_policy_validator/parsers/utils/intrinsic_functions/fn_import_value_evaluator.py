"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError


class ImportValueEvaluator:
	def __init__(self, node_evaluator, region):
		self.node_evaluator = node_evaluator
		self.cloudformation_client = client.build('cloudformation', region)

	def evaluate(self, value, visited_values=None):
		if visited_values is None:
			visited_values = []

		imported_value = self.node_evaluator.eval(value, visited_values=visited_values)

		paginator = self.cloudformation_client.get_paginator('list_exports')
		response_iterator = paginator.paginate()
		for page in response_iterator:
			exports = page['Exports']
			for export in exports:
				if export['Name'] == imported_value:
					return export['Value']

		raise ApplicationError(f'Unable to resolve Fn::ImportValue. Could not find a stack export to import with value {imported_value}.')
