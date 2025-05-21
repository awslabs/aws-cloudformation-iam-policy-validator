"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError


backup_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'backup:*',
            'Resource': 'arn:aws:backup:us-east-1:123456789012:backup-vault:MyTestVault',
            'Principal': '*',
            'Condition': {
                'ArnEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::123456789012:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}


backup_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 'backup:*',
            'Resource': [
                {"Fn::GetAtt": ["MyBackupVault", "BackupVaultArn"]},
                {"Fn::Sub": 'arn:aws:backup:::backup-vault:${MyBackupVault}'}
            ],
            'Principal': '*',
            'Condition': {
                'ArnNotEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::123456789012:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}

class WhenParsingABackupVaultPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_backup_vault_name(self):
        template = load_resources({
                'ResourceA': {
                    'Type': 'AWS::Backup::BackupVault',
                    'Properties': {
                        'AccessPolicy': copy.deepcopy(backup_policy_with_no_reference)
                    }
                }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('BackupVaultName', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_backup_vault_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': ['MyVault'],
                    'AccessPolicy': copy.deepcopy(backup_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.BackupVaultName', 'string', "['MyVault']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_access_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': 'MyVault',
                    'AccessPolicy': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.AccessPolicy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': 'MyVault',
                    'AccessPolicy': copy.deepcopy(backup_policy_with_no_reference),
                    'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')

    @mock_node_evaluator_setup()
    def test_with_ref_to_parameter_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': 'MyVault',
                    'AccessPolicy': copy.deepcopy(backup_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingABackupVaultPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load_resources({
                'TestVault': {
                    'Type': 'AWS::Backup::BackupVault',
                    'Properties': {
                        'BackupVaultName': 'MyVault',
                        'AccessPolicy': copy.deepcopy(backup_policy_with_no_reference)
                    }
                }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyVault", resource.ResourceName)
        self.assertEqual('AWS::Backup::BackupVault', resource.ResourceType)

        self.assertEqual('AccessPolicy', resource.Policy.Name)
        self.assertEqual(backup_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingABackupVaultPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a backup vault
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyBackupVault': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': 'MyCustomVaultName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::Backup::BackupVault',
                'Properties': {
                    'BackupVaultName': {'Ref': 'MyBackupVault'},
                    'AccessPolicy': copy.deepcopy(backup_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomVaultName", resource.ResourceName)
        self.assertEqual('AWS::Backup::BackupVault', resource.ResourceType)

        expected_policy = copy.deepcopy(backup_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:backup:{account_config.region}:{account_config.account_id}:backup-vault:MyCustomVaultName',
            'arn:aws:backup:::backup-vault:MyCustomVaultName'
        ]
        self.assertEqual('AccessPolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingABackupVaultWithNoAccessPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_no_resources(self):
        template = load_resources({
                'TestVault': {
                    'Type': 'AWS::Backup::BackupVault',
                    'Properties': {
                        'BackupVaultName': 'MyVault'
                    }
                }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 0)