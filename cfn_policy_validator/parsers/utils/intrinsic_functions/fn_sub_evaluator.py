"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import re

from cfn_policy_validator.application_error import SchemaValidationError
from cfn_policy_validator.cfn_tools import regex_patterns
from cfn_policy_validator.cfn_tools.cfn_object import CfnObject
from cfn_policy_validator.cfn_tools.common_schema import string_schema
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema


def validate_fn_sub_schema(value):
	try:
		validate_schema(value, sub_schema, 'Fn::Sub')
	except SchemaValidationError as e:
		if "is not of type 'array'" in str(e):
			# since GetAtt has multiple schemas, provide a custom error message that includes both schema options.
			# AnyOf just raises an arbitrary schema as an error.
			raise SchemaValidationError(f"{value} is not of type 'array or string', Path: Fn::Sub")
		else:
			raise


class SubEvaluator:
	def __init__(self, ref_evaluator, get_att_evaluator, node_evaluator):
		self.get_att_evaluator = get_att_evaluator
		self.ref_evaluator = ref_evaluator
		self.node_evaluator = node_evaluator

	def evaluate(self, value: CfnObject, visited_values: list = None):
		if visited_values is None:
			visited_values = []

		validate_fn_sub_schema(value)

		# There are two ways or writing a Fn::Sub function, a list and a string
		if isinstance(value, list):
			# a Fn::Sub with a list value has a variable map
			string_to_evaluate = value[0]
			variable_mapping = value[1]

			variables_in_string = re.findall(regex_patterns.fn_sub_variables, string_to_evaluate)
			for variable_in_string in variables_in_string:
				variable_value = variable_mapping.get(variable_in_string)
				if variable_value is not None:
					variable_value = self.node_evaluator.eval_with_validation(variable_value, string_schema, visited_values=visited_values)
					string_to_evaluate = string_to_evaluate.replace("${" + variable_in_string + "}", variable_value)
				else:
					# this will throw if it can't find the variable anywhere
					string_to_evaluate = self._evaluate_ref_or_get_att_in_sub(string_to_evaluate, variable_in_string, visited_values)

			return string_to_evaluate
		else:
			# the sub is a string value
			variables_in_string = re.findall(regex_patterns.fn_sub_variables, value)
			for variable_in_string in variables_in_string:
				value = self._evaluate_ref_or_get_att_in_sub(value, variable_in_string, visited_values)

			return value

	def _evaluate_ref_or_get_att_in_sub(self, value, variable_in_string, visited_values):
		if '.' in variable_in_string:
			# e.g. variable is MyResource.Arn
			variable_value = self.get_att_evaluator.evaluate(variable_in_string.split('.'), visited_values=visited_values)
		else:
			# e.g. variable is just MyResource
			variable_value = self.ref_evaluator.evaluate(variable_in_string, visited_values=visited_values)

		# validate the evaluated value is a string
		validate_schema(variable_value, string_schema, 'Fn::Sub')
		return value.replace("${" + variable_in_string + "}", variable_value)


sub_with_variable_map_schema = {
	"type": "array",
	"items": [
		{"type": "string"},
		{"type": "object"}
	],
	"additionalItems": False
}

sub_without_variable_map_schema = {
	"type": "string"
}


sub_schema = {
	"anyOf": [
		sub_with_variable_map_schema,
		sub_without_variable_map_schema
	]
}
