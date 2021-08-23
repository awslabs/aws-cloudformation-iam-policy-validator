"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

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
        self.roles, self.users, self.groups, self.orphaned_policies = \
            IdentityParser.parse(template, account_config)

    def assertResults(self, number_of_roles=0, number_of_users=0, number_of_groups=0,
                      number_of_orphaned_policies=0):
        self.assertEqual(len(self.users), number_of_users, "Expected number of users not equal.")
        self.assertEqual(len(self.groups), number_of_groups, "Expected number of groups not equal.")
        self.assertEqual(len(self.roles), number_of_roles, "Expected number of roles not equal.")
        self.assertEqual(len(self.orphaned_policies), number_of_orphaned_policies, "Expected number of orphaned policies not equal.")


# General template tests
class WhenParsingANonIAMResource(IdentityParserTest):
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
def get_policy_side_effect(*, PolicyArn):
    if PolicyArn == 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole':
        return {
            'Policy': {
                'PolicyName': 'AWSLambdaBasicExecutionRole',
                'DefaultVersionId': 'v1',
                'Path': '/service-role/'
            }
        }
    if PolicyArn == 'arn:aws:iam::aws:policy/AWSLambdaExecute':
        return {
            'Policy': {
                'PolicyName': 'AWSLambdaExecute',
                'DefaultVersionId': 'v2',
                'Path': '/'
            }
        }

    raise Exception('Policy ARN does not match any expected ARNs in get_policy call')


def get_policy_version_side_effect(*, PolicyArn, VersionId):
    if PolicyArn == 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'\
            and VersionId == 'v1':
        return {
            'PolicyVersion': {
                'Document': copy.deepcopy(sample_policy_a)
            }
        }
    if PolicyArn == 'arn:aws:iam::aws:policy/AWSLambdaExecute'\
            and VersionId == 'v2':
        return {
            'PolicyVersion': {
                'Document': copy.deepcopy(sample_policy_b)
            }
        }

    raise Exception('Policy ARN does not match any expected ARNs')



