import copy
import unittest

from cfn_policy_validator.tests import account_config
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup
from cfn_policy_validator.tests.utils import load_resources, build_node_evaluator


class WhenEvaluatingUrlSuffixForDefaultRegions(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_default_url_suffix(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Ref': 'AWS::URLSuffix'
					}
				}
			}
		})

		node_evaluator = build_node_evaluator(template)
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual('amazonaws.com', result['Properties']['PropertyA'])


class WhenEvaluatingUrlSuffixForChinaRegions(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_china_specific_url_suffix(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Random::Service',
				'Properties': {
					'PropertyA': {
						'Ref': 'AWS::URLSuffix'
					}
				}
			}
		})

		copy_of_account_config = copy.deepcopy(account_config)
		copy_of_account_config.region = 'cn-north-1'
		node_evaluator = build_node_evaluator(template, custom_account_config=copy_of_account_config)
		result = node_evaluator.eval(template['Resources']['ResourceA'])
		self.assertEqual('amazonaws.com.cn', result['Properties']['PropertyA'])
