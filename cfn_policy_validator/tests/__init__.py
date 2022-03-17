"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import boto3
import unittest

from cfn_policy_validator import AccountConfig
from cfn_policy_validator.tests.boto_mocks import mock_test_setup, BotoResponse, get_test_mode, TEST_MODE

if get_test_mode() == TEST_MODE.AWS:
    sts_client = boto3.client('sts')
    my_account_id = sts_client.get_caller_identity()['Account']
    s3_client = boto3.client('s3')
    my_canonical_user_id = s3_client.list_buckets()['Owner']['ID']
else:
    my_account_id = '111222333444'
    my_canonical_user_id = 'ABC12345'

account_config = AccountConfig('aws', 'us-east-2', my_account_id)


def end_to_end(func):
    def decorator(*args):
        self = args[0]
        if get_test_mode() == TEST_MODE.AWS:
            # only run when the integration environment variable is set
            func(self)
        else:
            raise unittest.SkipTest("Running in offline mode.  Skipping end to end test.")

    return decorator


def only_run_for_end_to_end(func):
    """
    Similar to the above end_to_end method but does not raise a unittest.SkipTest
    """
    def decorator(*args, **kwargs):
        if get_test_mode() == TEST_MODE.AWS:
            # only run when the integration environment variable is set
            func(*args, **kwargs)

    return decorator


def offline_only(func):
    def decorator(*args):
        self = args[0]
        if get_test_mode() == TEST_MODE.OFFLINE:
            # only run using mocks.  this is used for tests where setup is difficult and not worth it.
            func(self)
        else:
            raise unittest.SkipTest("Running in end to end mode.  Skipping offline test.")

    return decorator


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

    def assert_permission_set(self, permission_set_name, number_of_policies):
        permission_sets = self.output['PermissionSets']

        permission_set_exists = any(
            permission_set['Name'] == permission_set_name and
            len(permission_set['Policies']) == number_of_policies
            for permission_set in permission_sets
        )

        self.assertTrue(permission_set_exists, f'Could not find permission set with {permission_set_name}, {number_of_policies}.')

    def assert_resource(self, resource_name, resource_type, configuration=None):
        resources = self.output['Resources']

        resource = next((resource for resource in resources if
                        resource['ResourceName'] == resource_name and
                        resource['ResourceType'] == resource_type and
                        'Policy in resource'), None)

        self.assertIsNotNone(resource, f'Could not find resource with {resource_name} and {resource_type}.')
        if configuration is None:
            # metadata should only be visible in the output if it has a value
            self.assertNotIn('Configuration', resource, 'Configuration found in resource and should not exist in output.')
        else:
            self.assertEqual(configuration, resource['Configuration'])

    def assert_orphaned_policy(self, policy_name):
        policies = self.output['OrphanedPolicies']

        policy_exists = any(
            policy['Name'] == policy_name and
            'Policy' in policy
            for policy in policies
        )

        self.assertTrue(policy_exists, f'Could not find orphaned policy with {policy_name}.')


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


def mock_validation_setup(**kwargs):
    if 'sts' not in kwargs:
        kwargs['sts'] = [
            BotoResponse(
                method='get_caller_identity',
                service_response={
                    'Account': account_config.account_id,
                    'Arn': f'arn:aws:iam::{account_config.account_id}:assumed-role/MyAssumedRole'
                }
            )
        ]

    return mock_test_setup(**kwargs)
