"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import json
import unittest

from cfn_policy_validator.tests.boto_mocks import BotoResponse
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup, mock_identity_parser_setup
from cfn_policy_validator.tests.utils import load, account_config, load_resources

from cfn_policy_validator.parsers.identity import IdentityParser


assume_role_policy_doc = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {
                'Service': 'codepipeline.amazonaws.com'
            },
            'Action': 'sts:AssumeRole'
        }
    ]
}

sample_policy_a = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'ec2:RunInstance',
            'Resources': '*'
        }
    ]
}

sample_policy_b = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': [
                'iam:CreateRole',
                'iam:UpdateRole'
            ],
            'Resources': '*'
        }
    ]
}


def has_policy(principal, name, document, path="/"):
    return any(policy for policy in principal.Policies if
               policy.Name == name and
               policy.Policy == document and
               policy.Path == path)


class IdentityParserTest(unittest.TestCase):
    def parse(self, template, account_config):
        self.roles, self.users, self.groups, self.permission_sets, self.orphaned_policies = \
            IdentityParser.parse(template, account_config)

    def assertResults(self, number_of_roles=0, number_of_users=0, number_of_groups=0,
                      number_of_orphaned_policies=0, number_of_permission_sets=0):
        self.assertEqual(number_of_users, len(self.users), "Expected number of users not equal.")
        self.assertEqual(number_of_groups, len(self.groups), "Expected number of groups not equal.")
        self.assertEqual(number_of_roles, len(self.roles), "Expected number of roles not equal.")
        self.assertEqual(number_of_permission_sets, len(self.permission_sets), "Expected number of permission sets not equal.")
        self.assertEqual(number_of_orphaned_policies, len(self.orphaned_policies), "Expected number of orphaned policies not equal.")


# General template tests
class WhenParsingANonIAMResource(IdentityParserTest):
    @mock_identity_parser_setup()
    def test_returns_no_output(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3::Bucket',
                    'Properties': {
                        'PropertyA': 'ValueA'
                    }
                }
            }
        })

        self.parse(template, account_config)
        self.assertResults()


class WhenParsingANonIAMResourceWithNoProperties(IdentityParserTest):
    @mock_identity_parser_setup()
    def test_returns_no_output(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::S3::Bucket'
                }
            }
        })

        self.parse(template, account_config)
        self.assertResults()


# IAM Managed Policy tests
def aws_lambda_basic_execution_response():
    return BotoResponse(
        method='get_policy',
        service_response={
            'Policy': {
                'PolicyName': 'AWSLambdaBasicExecutionRole',
                'DefaultVersionId': 'v1',
                'Path': '/service-role/'
            }
        },
        expected_params={
            'PolicyArn': 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        }
    )


def aws_lambda_basic_execution_version_response():
    return BotoResponse(
        method='get_policy_version',
        service_response={
            'PolicyVersion': {
                'Document': json.dumps(copy.deepcopy(sample_policy_a))
            }
        },
        expected_params={
            'PolicyArn': 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            'VersionId': 'v1'
        }
    )


def aws_lambda_execute_response():
    return BotoResponse(
        method='get_policy',
        service_response={
            'Policy': {
                'PolicyName': 'AWSLambdaExecute',
                'DefaultVersionId': 'v2',
                'Path': '/'
            }
        },
        expected_params={
            'PolicyArn': 'arn:aws:iam::aws:policy/AWSLambdaExecute'
        }
    )


def aws_lambda_execute_version_response():
    return BotoResponse(
        method='get_policy_version',
        service_response={
            'PolicyVersion': {
                'Document': json.dumps(copy.deepcopy(sample_policy_b))
            }
        },
        expected_params={
            'PolicyArn': 'arn:aws:iam::aws:policy/AWSLambdaExecute',
            'VersionId': 'v2'
        }
    )
