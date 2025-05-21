"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource

class ApiGatewayRestApiPolicyParser:
    """ AWS::ApiGateway::RestApi
    """
    
    def __init__(self):
        self.rest_api_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(rest_api_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties.get('Policy')
        if policy_document is None:
            # we don't need to parse resources that don't have policies and policy is optional
            return
        name = properties['Name']

        policy = Policy('Policy', policy_document)
        resource = Resource(name, 'AWS::ApiGateway::RestApi', policy)

        self.rest_api_policies.append(resource)

    def get_policies(self):
        return self.rest_api_policies
    
rest_api_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'Policy': {
                    'type': 'object'
                },
                'Name': {
                    'type': 'string'
                }
            },
            'required': ['Name']
        }
    },
    'required': ['Properties']
}