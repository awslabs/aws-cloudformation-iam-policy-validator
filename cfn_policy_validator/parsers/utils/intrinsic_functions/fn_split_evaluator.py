"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.common_schema import string_schema
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class SplitEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_values):
		validate_schema(value, split_schema, f'Fn::Split')

		delimiter = value[0]
		string_to_split = self.node_evaluator.eval_with_validation(value[1], string_schema, visited_values)

		return string_to_split.split(delimiter)


split_schema = {
	'type': 'array',
	'items': [
		{
			'type': 'string'
		},
		{}
	],
	'additionalItems': False
}