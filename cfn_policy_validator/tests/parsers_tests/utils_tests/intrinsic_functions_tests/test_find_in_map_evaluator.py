"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, expected_type_error, build_node_evaluator


class WhenEvaluatingAPolicyWithAFindInMapFunction(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_mapping_value(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA',
						'SecondLevelMappingKeyB': ['MappingValue1', 'MappingValue2']
					}
				},
				'MappingB': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKey': 'MappingValueB'
					}
				}
			},
			'Parameters': {
				'TopLevelMappingKey': {
					'Type': 'String'
				},
				'MappingName': {
					'Type': 'String'
				},
				'SecondLevelMappingKey': {
					'Type': 'String'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': ['MappingA', 'TopLevelMappingKey', 'SecondLevelMappingKeyA']
						},
						'PropertyB': {
							'Fn::FindInMap': ['MappingA', 'TopLevelMappingKey', 'SecondLevelMappingKeyB']
						},
						'PropertyC': {
							'Fn::FindInMap': [{'Ref': 'MappingName'}, {'Ref': 'TopLevelMappingKey'}, {'Ref': 'SecondLevelMappingKey'}]
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template, {
			'MappingName': 'MappingB', 'TopLevelMappingKey': 'TopLevelMappingKey', 'SecondLevelMappingKey': 'SecondLevelMappingKey'
		})

		result_a = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result_a, 'MappingValueA')

		result_b = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])
		self.assertEqual(result_b, ['MappingValue1', 'MappingValue2'])

		result_c = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyC'])
		self.assertEqual(result_c, 'MappingValueB')


class WhenEvaluatingAPolicyWithAFindInMapFunctionThatIsNotAList(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA'
					}
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': 'MappingA.TopLevelMappingKey.SecondLevelMappingKeyA'
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::FindInMap', 'array', "'MappingA.TopLevelMappingKey.SecondLevelMappingKeyA'"), str(context.exception))


class WhenEvaluatingAPolicyWithAFindInMapFunctionThatIsNotOfLength3(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA'
					}
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': ['MappingA', 'TopLevelMappingKey', 'SecondLevelMappingKeyA', 'MappingValueA']
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(
			"Additional items are not allowed ('MappingValueA' was unexpected), Path: Fn::FindInMap",
			str(context.exception))


class WhenEvaluatingAPolicyWithAFindInMapFunctionWithMapNameThatIsNotString(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA'
					}
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': [['MappingA'], 'TopLevelMappingKey', 'SecondLevelMappingKeyA']
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::FindInMap.0', 'string', "['MappingA']"), str(context.exception))


class WhenEvaluatingAPolicyWithAFindInMapFunctionWithTopLevelKeyThatIsNotString(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA'
					}
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': ['MappingA', ['TopLevelMappingKey'], 'SecondLevelMappingKeyA']
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::FindInMap.1', 'string', "['TopLevelMappingKey']"), str(context.exception))


class WhenEvaluatingAPolicyWithAFindInMapFunctionWithSecondLevelKeyThatIsNotString(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Mappings': {
				'MappingA': {
					'TopLevelMappingKey': {
						'SecondLevelMappingKeyA': 'MappingValueA'
					}
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': ['MappingA', 'TopLevelMappingKey', ['SecondLevelMappingKeyA']]
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::FindInMap.2', 'string', "['SecondLevelMappingKeyA']"), str(context.exception))


class WhenEvaluatingAPolicyWithAFindInMapFunctionAndMappingCannotBeFound(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_an_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::FindInMap': ['MappingA', 'TopLevelMappingKey', 'SecondLevelMappingKeyA']
						}
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(
			"Fn::FindInMap lookup failed. Unable to find value in Mappings.  Value: ['MappingA', 'TopLevelMappingKey', 'SecondLevelMappingKeyA']",
			str(context.exception))
