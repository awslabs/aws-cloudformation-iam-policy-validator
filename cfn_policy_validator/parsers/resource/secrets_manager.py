"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource


class SecretsManagerPolicyParser:
    """ AWS::SecretsManager::ResourcePolicy
    """
    def __init__(self):
        self.policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(secret_resource_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties['ResourcePolicy']
        secret_arn = properties['SecretId']

        try:
            secret_name = secret_arn.split("secret:", 1)[1]
        except IndexError:
            raise ApplicationError(f'Invalid value for {resource.ancestors_as_string()}.Properties.SecretId. Must be a valid Secret ARN. SecretId value: {secret_arn}')

        policy = Policy('ResourcePolicy', policy_document)
        resource = Resource(secret_name, 'AWS::SecretsManager::Secret', policy)

        self.policies.append(resource)

    def get_policies(self):
        return self.policies


secret_resource_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'ResourcePolicy': {
                    'type': 'object'
                },
                'SecretId': {
                    'type': 'string'
                }
            },
            'required': ['ResourcePolicy', 'SecretId']
        }
    },
    'required': ['Properties']
}