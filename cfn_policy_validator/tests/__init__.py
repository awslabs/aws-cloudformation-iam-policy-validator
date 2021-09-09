"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
import unittest


from cfn_policy_validator import AccountConfig

sts_client = boto3.client('sts')
my_account_id = sts_client.get_caller_identity()['Account']
account_config = AccountConfig('aws', 'us-east-2', my_account_id)


s3_client = boto3.client('s3')
my_canonical_user_id = s3_client.list_buckets()['Owner']['ID']


class ParsingTest(unittest.TestCase):
    def assert_role(self, role_name, role_path, number_of_policies):
        roles = self.output['Roles']

        role_exists = any(
            role['RoleName'] == role_name and
            role['RolePath'] == role_path and
            len(role['Policies']) == number_of_policies and
            'TrustPolicy' in role
            for role in roles
        )

        self.assertTrue(role_exists, f'Could not find role with {role_name}, {role_path}, {number_of_policies}.')

    def assert_user(self, user_name, user_path, number_of_policies):
        users = self.output['Users']

        user_exists = any(
            user['UserName'] == user_name and
            user['UserPath'] == user_path and
            len(user['Policies']) == number_of_policies
            for user in users
        )

        self.assertTrue(user_exists, f'Could not find user with {user_name}, {user_path}, {number_of_policies}.')

    def assert_group(self, group_name, group_path, number_of_policies):
        groups = self.output['Groups']

        group_exists = any(
            group['GroupName'] == group_name and
            group['GroupPath'] == group_path and
            len(group['Policies']) == number_of_policies
            for group in groups
        )

        self.assertTrue(group_exists, f'Could not find group with {group_name}, {group_path}, {number_of_policies}.')

    def assert_resource(self, resource_name, resource_type):
        resources = self.output['Resources']

        resource_exists = any(
            resource['ResourceName'] == resource_name and
            resource['ResourceType'] == resource_type and
            'Policy' in resource
            for resource in resources
        )

        self.assertTrue(resource_exists, f'Could not find resource with {resource_name} and {resource_type}.')

    def assert_orphaned_policy(self, policy_name):
        policies = self.output['OrphanedPolicies']

        policy_exists = any(
            policy['Name'] == policy_name and
            'Policy' in policy
            for policy in policies
        )

        self.assertTrue(policy_exists, f'Could not find orphaned policy with {policy_name}.')


# this test runs through an entire happy path
class ValidationTest(unittest.TestCase):
    def assert_warning(self, finding_type, code, resource_name, policy_name):
        self.assert_finding(self.output['NonBlockingFindings'], finding_type, code, resource_name, policy_name)

    def assert_error(self, finding_type, code, resource_name, policy_name):
        self.assert_finding(self.output['BlockingFindings'], finding_type, code, resource_name, policy_name)

    def assert_finding(self, findings, finding_type, code, resource_name, policy_name):
        finding_exists = any(
            finding['code'] == code and
            finding['findingType'] == finding_type and
            finding['resourceName'] == resource_name and
            finding['policyName'] == policy_name
            for finding in findings
        )

        self.assertTrue(finding_exists, f'Could not find finding with {finding_type}, {code}, {resource_name}, {policy_name}.')
