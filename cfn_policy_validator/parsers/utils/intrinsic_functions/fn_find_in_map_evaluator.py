"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.common_schema import string_schema
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class FindInMapEvaluator:
	def __init__(self, mappings, node_evaluator):
		self.node_evaluator = node_evaluator
		self.mappings = mappings

	def evaluate(self, value, visited_values):
		validate_schema(value, find_in_map_schema, 'Fn::FindInMap')

		# these hardcoded path names help with debugging if there are eval issues
		map_name = self.node_evaluator.eval_with_validation(value[0], string_schema, path='Fn::FindInMap.0', visited_values=visited_values)
		top_level_key = self.node_evaluator.eval_with_validation(value[1], string_schema, path='Fn::FindInMap.1', visited_values=visited_values)
		second_level_key = self.node_evaluator.eval_with_validation(value[2], string_schema, path='Fn::FindInMap.2', visited_values=visited_values)

		result = self.mappings.get(map_name, {}) \
								.get(top_level_key, {}) \
								.get(second_level_key)

		if result is None:
			raise ApplicationError(f'Fn::FindInMap lookup failed. Unable to find value in Mappings.  Value: {value}')

		return result


find_in_map_schema = {
	'type': 'array',
	'items': [
		{},
		{},
		{}
	],
	'additionalItems': False
}
