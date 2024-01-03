"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class NotEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_nodes):
		validate_schema(value, not_schema, 'Fn::Not')

		evaluated = self.node_evaluator.eval(value[0], visited_nodes=visited_nodes)
		if not isinstance(evaluated, bool):
			raise ApplicationError('Could not evaluate Fn::Not. The evaluated value of a Not function must be a boolean. '
								   f'Value does not evaluate to a boolean: {value}')

		return not evaluated


not_schema = {
	'type': 'array',
	'items': [
		{}
	],
	'minItems': 1,
	'maxItems': 1
}
