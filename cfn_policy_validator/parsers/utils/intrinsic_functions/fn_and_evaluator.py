"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class AndEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_nodes):
		validate_schema(value, and_schema, 'Fn::And')

		result = True
		for index, and_candidate in enumerate(value):
			evaluated_value = self.node_evaluator.eval(and_candidate, visited_nodes)
			if not isinstance(evaluated_value, bool):
				raise ApplicationError('Could not evaluate Fn::And. All values of an AND function must be booleans. '
									   f'Value at index {index} does not evaluate to a boolean: {value}')

			result = result and evaluated_value

		return result


and_schema = {
	'type': 'array',
	'items': [
		{}
	],
	'minItems': 2,
	'maxItems': 10
}
