"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.parsers.output import Policy, Resource


class KmsKeyPolicyParser:
    """ AWS::KMS::Key
    """

    def __init__(self):
        self.key_policies = []

    def parse(self, resource_name, resource):
        evaluated_resource = resource.eval(key_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties['KeyPolicy']

        policy = Policy('KeyPolicy', policy_document)
        resource = Resource(resource_name, 'AWS::KMS::Key', policy)

        self.key_policies.append(resource)

    def get_policies(self):
        return self.key_policies


key_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'KeyPolicy': {
                    'type': 'object'
                }
            },
            'required': ['KeyPolicy']
        }
    },
    'required': ['Properties']
}
