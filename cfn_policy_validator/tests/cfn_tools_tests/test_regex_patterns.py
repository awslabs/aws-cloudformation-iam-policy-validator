"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest
from cfn_policy_validator.cfn_tools import regex_patterns


class GenericArnPatternTest(unittest.TestCase):
	def assert_matches(self, arn):
		self.assertIsNotNone(regex_patterns.generic_arn_pattern.match(arn), f'{arn} does not match arn pattern.')

	def assert_does_not_match(self, arn):
		self.assertIsNone(regex_patterns.generic_arn_pattern.match(arn), f'{arn} matches arn pattern when it should not.')

	def test_matches_gov_cloud(self):
		arn = "arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:ProcessKinesisRecords"
		self.assert_matches(arn)

	def test_matches_china(self):
		arn = "arn:aws-cn:rds:cn-north-1:123456789012:db:mysql-db"
		self.assert_matches(arn)

	def test_does_not_match_invalid_partition(self):
		arn = "arn:qws:iam::123456789012:role/MyRole"
		self.assert_does_not_match(arn)

	def test_matches_arbitrary_service(self):
		arn = "arn:aws:iam::123456789012:abcdef/MyRole"
		self.assert_matches(arn)

	def test_matches_no_region(self):
		arn = "arn:aws:iam::123456789012:abcdef/MyRole"
		self.assert_matches(arn)

	def test_matches_region(self):
		arn = "arn:aws:greengrass:us-east-1:123456789012:/greengrass/groups/abc"
		self.assert_matches(arn)

	def test_matches_arbitrary_resource(self):
		arn = "arn:aws:greengrass:us-east-1:123456789012:does_not_matter"
		self.assert_matches(arn)

	def test_does_not_match_missing_arn(self):
		arn = "aws:iam::123456789012:abcdef/MyRole"
		self.assert_does_not_match(arn)

	def test_does_not_match_missing_partition(self):
		arn = "arn:iam::123456789012:abcdef/MyRole"
		self.assert_does_not_match(arn)

	def test_does_not_match_missing_region(self):
		arn = "arn:aws:iam:123456789012:abcdef/MyRole"
		self.assert_does_not_match(arn)

	def test_does_not_match_missing_account_id(self):
		arn = "arn:aws:iam::abcdef/MyRole"
		self.assert_does_not_match(arn)

	def test_does_not_match_missing_resource_path(self):
		arn = "arn:aws:iam::123456789012"
		self.assert_does_not_match(arn)

	def test_captures_group(self):
		arn = "arn:aws:iam::123456789012:abcdef/MyRole"
		match = regex_patterns.generic_arn_pattern.match(arn)

		self.assertEqual('123456789012', match.group(1))
