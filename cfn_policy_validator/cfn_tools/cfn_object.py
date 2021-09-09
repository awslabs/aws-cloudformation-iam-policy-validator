"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from typing import Any


class CfnObject(dict):
	"""
	A representation of a JSON/YAML object that is aware of some context of where it exists in the template. Simplifies
	evaluations, allows for clearer error messages on failures, and avoids passing the node_evaluator around everywhere.
	"""

	def __init__(self, value={}):
		super(CfnObject, self).__init__(value)
		self.ancestors = []
		self.node_evaluator = None

	def add_ancestors(self, parent_ancestors: list, parent_key: str):
		self.ancestors = list(parent_ancestors)
		if parent_key is not None and parent_key != 'Resources':
			self.ancestors.append(parent_key)

	def set_node_evaluator(self, node_evaluator):
		self.node_evaluator = node_evaluator

	@property
	def parent(self):
		parent = self.ancestors[-1:]
		if len(parent) == 0:
			return None

		return parent[0]

	def eval(self, expected_schema: Any, visited_values: list = None):
		path = self.ancestors_as_string()

		resource_properties = self._find_resource_properties_in_schema(expected_schema)
		if resource_properties is not None:
			resource_properties = list(resource_properties.keys())

		return self.node_evaluator.eval_with_validation(self, expected_schema, resource_properties_to_eval=resource_properties, path=path, visited_values=visited_values)

	# iterate through schema and find the properties of the resource.  When we evaluate the resource, we only evaluate
	# the properties that we need to parse the policies
	def _find_resource_properties_in_schema(self, schema):
		properties = schema.get('properties')
		if properties is None:
			return None

		for key, value in properties.items():
			if key == 'Properties':
				return properties[key].get('properties')

			return self._find_resource_properties_in_schema(properties[key])

	def ancestors_as_string(self):
		if len(self.ancestors) == 0:
			return "Template"

		return ".".join(self.ancestors)
