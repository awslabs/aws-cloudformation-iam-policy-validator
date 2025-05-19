"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource

class CodeArtifactDomainPolicyParser:
    """ AWS::CodeArtifact::Domain
    """
    
    def __init__(self):
        self.code_artifact_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(code_artifact_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties.get('PermissionsPolicyDocument')
        if policy_document is None:
            # we don't need to parse resources that don't have policies and policy is optional
            return
        name = properties['DomainName']

        policy = Policy('PermissionsPolicyDocument', policy_document)
        resource = Resource(name, 'AWS::CodeArtifact::Domain', policy)

        self.code_artifact_policies.append(resource)

    def get_policies(self):
        return self.code_artifact_policies
    
code_artifact_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'PermissionsPolicyDocument': {
                    'type': 'object'
                },
                'DomainName': {
                    'type': 'string'
                }
            },
            'required': ['DomainName']
        }
    },
    'required': ['Properties']
}