"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import io
import unittest

import yaml

from cfn_policy_validator.cfn_tools.yaml_loader import CfnYamlLoader


class WhenParsingYaml(unittest.TestCase):
	@staticmethod
	def load(template):
		stream = io.StringIO(template)
		return yaml.load(stream, Loader=CfnYamlLoader)

	def assert_parsed_result_is_expected(self, expected_template, raw_template):
		loaded_template = self.load(raw_template)
		self.assertEqual(expected_template, loaded_template)

	def test_sub_shorthand_for_short_form_is_replaced(self):
		raw_template = """
!Sub string
"""
		expected_template = {
			'Fn::Sub': 'string'
		}

		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_sub_shorthand_for_long_form_is_replaced(self):
		raw_template = """
!Sub
  - String
  -  Var1Name: Var1Value
     Var2Name: Var2Value
"""
		expected_template = {
			'Fn::Sub': ['String', {'Var1Name': 'Var1Value', 'Var2Name': 'Var2Value'}]
		}

		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_ref_shorthand_is_replaced(self):
		raw_template = """
!Ref string
"""
		expected_template = {
			'Ref': 'string'
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_find_in_map_shorthand_is_replaced(self):
		raw_template = """
!FindInMap [MapName, TopLevelKey, SecondLevelKey]
"""
		expected_template = {
			'Fn::FindInMap': ['MapName', 'TopLevelKey', 'SecondLevelKey']
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_get_att_shorthand_is_replaced(self):
		raw_template = """
!GetAtt logicalResourceName.attributeName
"""
		expected_template = {
			'Fn::GetAtt': ['logicalResourceName', 'attributeName']
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_import_value_shorthand_is_replaced(self):
		raw_template = """
!ImportValue sharedValueToImport
"""
		expected_template = {
			'Fn::ImportValue': 'sharedValueToImport'
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_join_shorthand_is_replaced(self):
		raw_template = """
!Join
  - ","
  -  - value1
     - value2
"""
		expected_template = {
			'Fn::Join': [',', ['value1', 'value2']]
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_select_shorthand_is_replaced(self):
		raw_template = """
!Select
  - 0
  - - object1
    - object2
"""
		expected_template = {
			'Fn::Select': [0, ['object1', 'object2']]
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_split_shorthand_is_replaced(self):
		raw_template = """
!Split
  - "|"
  - a|b|c
"""
		expected_template = {
			'Fn::Split': ['|', 'a|b|c']
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)

	def test_dates_are_parsed_to_string(self):
		raw_template = """
Version: 2012-10-21
"""
		expected_template = {
			'Version': '2012-10-21'
		}
		self.assert_parsed_result_is_expected(expected_template, raw_template)
