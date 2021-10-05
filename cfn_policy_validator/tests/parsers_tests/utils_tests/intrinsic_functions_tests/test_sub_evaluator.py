"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load, account_config, load_resources, expected_type_error


class WhenEvaluatingAPropertyWithASubThatResolvesToGetAtt(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_string_value(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': 'This is a line of text with value ${ResourceB.Name}'
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::Lambda::Function',
					'Properties': {
						'Name': 'ExpectedValue'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'This is a line of text with value ExpectedValue')


class WhenEvaluatingAPropertyWithASubThatResolvesToRawDollarSignText(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_string_value(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Sub': 'This is a line of text with value ${!ResourceB.Name}'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, 'This is a line of text with value ${!ResourceB.Name}')


class WhenEvaluatingAPropertyWithASubThatResolvesToRef(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_arn(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': '${ResourceB}'
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::MSK::Cluster'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(result, f'arn:aws:kafka:{account_config.region}:{account_config.account_id}:cluster/ResourceB/ResourceB')


class WhenEvaluatingAPropertyWithASubThatDoesNotResolveToAString(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_arn(self):
		template = load({
			'Parameters': {
				'ParameterA': {
					'Type': 'String'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': '${ParameterA}'
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {
			'ParameterA': ['Invalid']
		})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::Sub', 'string', "['Invalid']"), str(cm.exception))


class WhenEvaluatingAPropertyWithALongFormSub(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_arn(self):
		template = load({
			'Parameters': {
				'DomainParam': {
					'Type': 'string'
				},
				'DomainParam2': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': ['www.${Domain}', {'Domain': {'Ref': 'DomainParam'}}]
						},
						'PropertyB': {
							'Fn::Sub': ['www.${Domain}.${Domain2}', {'Domain': {'Ref': 'DomainParam'}, 'Domain2': {'Ref': 'DomainParam2'}}]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {
			'DomainParam': 'MyValue',
			'DomainParam2': 'com'
		})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual('www.MyValue', result)

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])
		self.assertEqual('www.MyValue.com', result)


class WhenEvaluatingAPropertyWithALongTermSubAndSomeVariablesNotInMap(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_variable_values_in_priority_order(self):
		# variables in the map have precedence, but not all variables need to appear in map
		template = load({
			'Parameters': {
				'DomainParam': {
					'Type': 'string'
				},
				'DomainParam2': {
					'Type': 'string'
				},
				'OtherValue': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': [
								'www.${DomainParam}',
								{'DomainParam': {'Ref': 'OtherValue'}}
							]
						},
						'PropertyB': {
							'Fn::Sub': [
								'www.${Domain}.${Domain2}.${AWS::AccountId}.${OtherValue}.${ResourceB.PropertyB}',
								{'Domain': {'Ref': 'DomainParam'}, 'Domain2': {'Ref': 'DomainParam2'}}]
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyB': 'ValueB'
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {
			'DomainParam': 'MyValue',
			'DomainParam2': 'com',
			'OtherValue': 'other'
		})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual('www.other', result)

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])
		self.assertEqual(f'www.MyValue.com.{account_config.account_id}.other.ValueB', result)


class WhenEvaluatingLongFormSubAndVariableAppearsMoreThanOnce(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_substitutes_variable_values(self):
		template = load({
			'Parameters': {
				'DomainParam': {
					'Type': 'string'
				}
			},
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': [
								'www.${Domain}.${Domain}.${AWS::AccountId}',
								{'Domain': {'Ref': 'DomainParam'}, 'Domain2': {'Ref': 'DomainParam2'}}]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {
			'DomainParam': 'MyValue'
		})

		result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
		self.assertEqual(f'www.MyValue.MyValue.{account_config.account_id}', result)


class WhenEvaluatingLongFormSubAndGetAttIsNotFound(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_exception(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyB': {
							'Fn::Sub': [
								'www.${Domain}.${AWS::AccountId}.${ResourceB.PropertyB}',
								{'Domain': {'Ref': 'AWS::AccountId'}}
							]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])

		self.assertEqual('Unable to find referenced resource for GetAtt reference to ResourceB.PropertyB',
						 str(cm.exception))


class WhenEvaluatingLongFormSubAndRefIsNotFound(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_exception(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyB': {
							'Fn::Sub': [
								'www.${Domain}.${AWS::AccountId}.${MissingParam}',
								{'Domain': {'Ref': 'AWS::AccountId'}}
							]
						}
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as cm:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyB'])

		self.assertEqual('Unable to find a referenced resource or parameter in template: MissingParam',
						 str(cm.exception))


class WhenEvaluatingAPropertyWithInvalidSubValue(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': {'Ref': 'Invalid'}
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::MSK::Cluster'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::Sub', 'array or string', {'Ref': 'Invalid'}), str(context.exception))


class WhenEvaluatingAPropertyWithLongFormSubOfInvalidLength(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': ['www.${Domain}', {'Domain': "abc"}, "3rd"]
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::MSK::Cluster'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(
			"Additional items are not allowed ('3rd' was unexpected), Path: Fn::Sub",
			str(context.exception))


class WhenEvaluatingAPropertyWithLongFormSubWithInvalidTextToEvaluate(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_error(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Fn::Sub': [['www.${Domain}'], {'Domain': "abc"}]
					}
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error("Fn::Sub.0", 'string', "['www.${Domain}']"), str(context.exception))


class WhenEvaluatingAPropertyWithLongFormSubWithInvalidMapping(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': ['www.${Domain}', 'Domain']
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::MSK::Cluster'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(expected_type_error('Fn::Sub.1', 'object', "'Domain'"), str(context.exception))


class WhenEvaluatingAPropertyWithLongFormSubAndNoMatchingMapping(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_raises_error(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Random::Service',
					'Properties': {
						'PropertyA': {
							'Fn::Sub': ['www.${Domain}', {'Romain': "abc"}]
						}
					}
				},
				'ResourceB': {
					'Type': 'AWS::MSK::Cluster'
				}
			}
		})

		node_evaluator = NodeEvaluator(template, account_config, {})

		with self.assertRaises(ApplicationError) as context:
			node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

		self.assertEqual(
			"Unable to find a referenced resource or parameter in template: Domain",
			str(context.exception))
