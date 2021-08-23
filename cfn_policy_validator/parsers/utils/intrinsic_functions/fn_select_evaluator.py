"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


class SelectEvaluator:
	def __init__(self, node_evaluator):
		self.node_evaluator = node_evaluator

	def evaluate(self, value, visited_values):
		validate_schema(value, select_schema, 'Fn::Select')

		try:
			index = self.node_evaluator.eval(value[0], visited_values=visited_values)
			index = int(index)
		except ValueError:
			raise ApplicationError(f'The first value for Fn::Select must be an integer. Invalid value: {value[0]}')

		list_of_objects = self.node_evaluator.eval_with_validation(value[1], list_of_objects_schema, path='Fn::Select.1', visited_values=visited_values)

		if index >= len(list_of_objects) or index < 0:
			raise ApplicationError(f'Fn::Select index is out of bounds of the list.  Invalid value: {value}')

		return self.node_evaluator.eval(list_of_objects[index], visited_values)


select_schema = {
	'type': 'array',
	'items': [
		# both index and list_of_objects can contain references
		{},
		{}
	],
	'additionalItems': False
}

index_schema = {
	'type': 'integer'
}

list_of_objects_schema = {
	'type': 'array'
}
