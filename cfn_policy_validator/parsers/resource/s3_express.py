"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource
import logging

LOGGER = logging.getLogger("cfn-policy-validator")

class S3ExpressAccessPointPolicyParser:
    """ AWS::S3Express::AccessPoint
    """
    
    def __init__(self):
        self.access_point_policies = []

    def parse(self, resourceName, resource):
        evaluated_resource = resource.eval(s3_express_access_point_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties.get('Policy')
        if policy_document is None:
            # we don't need to parse resources that don't have policies and policy is optional
            return
        
        name = properties.get('Name', resourceName)
        policy = Policy('Policy', policy_document)
        vpc_id = properties.get('VpcConfiguration', {}).get('VpcId')
        
        configuration = None
        if vpc_id is not None:
            configuration = {
                'VpcId': vpc_id
            }
        
        resource = Resource(name, 'AWS::S3Express::AccessPoint', policy, configuration)

        self.access_point_policies.append(resource)

    def get_policies(self):
        return self.access_point_policies
    
s3_express_access_point_policy_schema = {
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
                },
                'VpcConfiguration': {
                    'type': 'object'
                }
            }
        }
    },
    'required': ['Properties']
}