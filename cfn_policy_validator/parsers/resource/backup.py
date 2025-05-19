"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource

class BackupBackupVaultPolicyParser:
    """ AWS::Backup::BackupVault
    """
    
    def __init__(self):
        self.backup_vault_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(backup_vault_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties.get('AccessPolicy')
        if policy_document is None:
            # we don't need to parse resources that don't have policies and policy is optional
            return
        name = properties['BackupVaultName']

        policy = Policy('AccessPolicy', policy_document)
        resource = Resource(name, 'AWS::Backup::BackupVault', policy)
        self.backup_vault_policies.append(resource)

    def get_policies(self):
        return self.backup_vault_policies
    
backup_vault_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'AccessPolicy': {
                    'type': 'object'
                },
                'BackupVaultName': {
                    'type': 'string'
                }
            },
            'required': ['BackupVaultName']
        }
    },
    'required': ['Properties']
}