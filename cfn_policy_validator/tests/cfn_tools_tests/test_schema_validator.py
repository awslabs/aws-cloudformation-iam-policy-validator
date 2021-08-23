"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import io
import json
import unittest
import yaml

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate
from cfn_policy_validator.cfn_tools.yaml_loader import CfnYamlLoader
from cfn_policy_validator.tests.utils import expected_type_error, required_property_error


def load(template):
	stream = io.StringIO(json.dumps(template))
	return yaml.load(stream, Loader=CfnYamlLoader)


class WhenParsingTemplateAndValidatingSchema(unittest.TestCase):
	def test_template_has_no_resources(self):
		template = load({})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("'Resources' is a required property", str(cm.exception))

	def test_template_has_invalid_resources_type(self):
		template = load({
			'Resources': []
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("[] is not of type 'object', Path: Resources", str(cm.exception))

	def test_template_has_valid_resources_type(self):
		template = load({
			'Resources': {}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_invalid_resource_type(self):
		template = load({
			'Resources': {
				'ResourceA': []
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("[] is not of type 'object', Path: Resources.ResourceA", str(cm.exception))

	def test_template_has_valid_resource_type(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Policy'
				}
			}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_resources_have_no_type(self):
		template = load({
			'Resources': {
				'ResourceA': {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual(required_property_error('Type', 'Resources.ResourceA'), str(cm.exception))

	def test_template_resources_have_invalid_type(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': ['Invalid']
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual(expected_type_error('Resources.ResourceA.Type', 'string', "['Invalid']"), str(cm.exception))

	def test_template_resources_have_valid_type(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Role'
				}
			}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_resources_have_invalid_properties_type(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::IAM::Role',
					'Properties': []
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual(expected_type_error('Resources.ResourceA.Properties', 'object', "[]"), str(cm.exception))

	def test_template_has_non_alphanumeric_resource_name(self):
		template = load({
			'Resources': {
				'Resource_A': {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("'Resource_A' does not match any of the regexes: '^[a-zA-Z0-9]+$', Path: Resources", str(cm.exception))

	def test_template_has_no_parameters(self):
		template = load({
			'Resources': {}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_invalid_parameters_type(self):
		template = load({
			'Resources': {},
			'Parameters': []
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("[] is not of type 'object', Path: Parameters", str(cm.exception))

	def test_template_has_no_mappings(self):
		template = load({
			'Resources': {}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_no_first_level_mappings(self):
		template = load({
			'Resources': {},
			'Mappings': {}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_invalid_first_level_mappings_type(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": 'string'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("'string' is not of type 'object', Path: Mappings.FirstLevel1", str(cm.exception))

	def test_template_has_invalid_first_level_mapping_name(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"us-east-1": {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("'us-east-1' does not match any of the regexes: '^[a-zA-Z0-9]+$', Path: Mappings", str(cm.exception))

	def test_template_has_no_second_level_mapping(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("{} does not have enough properties, Path: Mappings.FirstLevel1", str(cm.exception))

	def test_template_has_invalid_second_level_mappings_type(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'SecondLevel1': 'string'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("'string' is not of type 'object', Path: Mappings.FirstLevel1.SecondLevel1", str(cm.exception))

	def test_template_has_no_third_level_mapping(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'SecondLevel1': {}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("{} does not have enough properties, Path: Mappings.FirstLevel1.SecondLevel1", str(cm.exception))

	def test_template_has_invalid_third_level_mappings_type(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'SecondLevel1': {
						'ThirdLevel1': {}
					}
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			validate(template)

		self.assertEqual("{} is not of type 'string', 'array', Path: Mappings.FirstLevel1.SecondLevel1.ThirdLevel1", str(cm.exception))

	def test_template_has_valid_string_mapping(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'SecondLevel1': {
						'ThirdLevel1': 'valid'
					}
				}
			}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_valid_mapping_names(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'us-east-1': {
						'super-large': 'valid',
						'c1.xlarge': 'abc'
					}
				}
			}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")

	def test_template_has_valid_list_mapping(self):
		template = load({
			'Resources': {},
			'Mappings': {
				"FirstLevel1": {
					'SecondLevel1': {
						'ThirdLevel1': ['valid1', 'valid2']
					}
				}
			}
		})

		validate(template)

		self.assertTrue(True, "No application error raised.")
