"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.cfn_object import CfnObject


class NoValue:
	"""
	This is a placeholder used to replace a reference to NoValue - {"Ref": "NoValue"}.  These placeholders (and dict keys
	that reference them) are removed from the evaluated output after resource evaluation.
	"""
	pass


class AwsNoValueEvaluator:
	"""
	Removes any references to NoValue from the evaluated output.  If a dictionary key has a NoValue reference, the key
	is also removed.
	"""
	def evaluate(self, value):
		if isinstance(value, dict):
			for key in list(value.keys()):
				child_value = value[key]
				if isinstance(child_value, NoValue):
					del value[key]
				else:
					self.evaluate(child_value)

		elif isinstance(value, list):
			for item in value:
				self.evaluate(item)

			# mutate the list to remove any item that is NoValue
			# must be done outside of the above for loop
			value[:] = [item for item in value if not isinstance(item, NoValue)]

		return value
