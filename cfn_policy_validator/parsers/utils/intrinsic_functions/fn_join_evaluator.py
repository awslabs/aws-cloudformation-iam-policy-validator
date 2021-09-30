"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.common_schema import array_of_strings_schema
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class JoinEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_values):
		validate_schema(value, join_schema, 'Fn::Join')

		delimiter = value[0]
		list_of_values = value[1]

		list_of_evaluated_values = self.node_evaluator.eval_with_validation(list_of_values, array_of_strings_schema,
																			path='Fn::Join.1', visited_values=visited_values)

		return delimiter.join(list_of_evaluated_values)


join_schema = {
	'type': 'array',
	'items': [
		{
			'type': 'string'
		},
		{}
	],
	'additionalItems': False
}
