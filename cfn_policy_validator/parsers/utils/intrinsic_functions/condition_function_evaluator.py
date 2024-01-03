"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class ConditionFunctionEvaluator:
	def __init__(self, condition_evaluator):
		self.condition_evaluator = condition_evaluator

	def evaluate(self, value, visited_nodes):
		validate_schema(value, condition_function_schema, 'Condition')
		return self.condition_evaluator.eval(value, visited_nodes)


condition_function_schema = {
	'type': 'string',
	'additionalItems': False
}
