"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class EqualsEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_nodes):
		validate_schema(value, equals_schema, 'Fn::Equals')

		first_value = value[0]
		second_value = value[1]

		first_value_evaluated = self.node_evaluator.eval(first_value, visited_nodes=visited_nodes)
		second_value_evaluated = self.node_evaluator.eval(second_value, visited_nodes=visited_nodes)

		return str(first_value_evaluated) == str(second_value_evaluated)


equals_schema = {
	'type': 'array',
	'minItems': 2,
	'maxItems': 2,
	'items': [
		{},
		{}
	],
	'additionalItems': False
}
