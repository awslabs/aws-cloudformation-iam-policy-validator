"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import load_resources

account_config = AccountConfig('aws', 'us-east-1', '123456789123')


class WhenParsingAResourceThatIsNotAResourcePolicy(unittest.TestCase):
	@mock_node_evaluator_setup()
	def test_returns_no_output(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::S3::Bucket',
				'Properties': {
					'PropertyA': 'ValueA'
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(0, len(resources))
