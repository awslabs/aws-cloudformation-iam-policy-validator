"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class IfEvaluator:
	def __init__(self, condition_evaluator, node_evaluator):
		self.node_evaluator = node_evaluator
		self.condition_evaluator = condition_evaluator

	def evaluate(self, value, visited_nodes):
		validate_schema(value, if_schema, 'Fn::If')

		condition_name = value[0]
		value_if_true = value[1]
		value_if_false = value[2]

		condition_is_true = self.condition_evaluator.eval(condition_name, visited_nodes)
		if condition_is_true:
			return self.node_evaluator.eval(value_if_true, visited_nodes=visited_nodes)
		else:
			return self.node_evaluator.eval(value_if_false, visited_nodes=visited_nodes)


if_schema = {
	'type': 'array',
	'items': [
		{
			'type': 'string'
		},
		{},
		{}
	],
	'minItems': 3,
	'maxItems': 3
}
