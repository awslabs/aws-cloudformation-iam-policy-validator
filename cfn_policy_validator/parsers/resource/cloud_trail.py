"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource
import re
from typing import Tuple, Optional

class CloudTrailResourcePolicyParser:
    """ AWS::CloudTrail::ResourcePolicy
    """
    
    def __init__(self):
        self.resource_policies = []
    
    @staticmethod
    def extract_cloudtrail_resource_info(arn) -> Optional[Tuple[str, str]]:
        """
        Extract both the resource type and resource name from a CloudTrail ARN.
        
        Args:
            arn (str): The CloudTrail ARN to parse
            
        Returns:
            Tuple[str, str] or None: A tuple containing (resource_type, resource_name) if match found,
                                    or None if no match
        """
        # Pattern captures both resource type and resource name
        pattern = r'arn:aws:cloudtrail:[^:]*:[^:]*:([^/]+)/([^/]+)'
        match = re.match(pattern, arn)
        
        if match:
            resource_type = match.group(1)  # Extract resource type
            resource_name = match.group(2)  # Extract resource name
            return resource_type, resource_name
        
        return None

    def parse(self, _, resource):
        evaluated_resource = resource.eval(resource_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties['ResourcePolicy']
        resource, name = self.extract_cloudtrail_resource_info(properties['ResourceArn'])
        supported_resource_types = {'dashboard': 'AWS::CloudTrail::Dashboard', 'eventdatastore':'AWS::CloudTrail::EventDataStore'}
        resource_type = supported_resource_types.get(resource)
        if resource_type is None:
            raise ApplicationError(f"Unsupported resource type {resource}")
        policy = Policy('ResourcePolicy', policy_document)
        resource = Resource(name, resource_type, policy)

        self.resource_policies.append(resource)

    def get_policies(self):
        return self.resource_policies
    
resource_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'ResourcePolicy': {
                    'type': 'object'
                },
                'ResourceArn': {
                    'type': 'string'
                }
            },
            'required': ['ResourcePolicy', 'ResourceArn']
        }
    },
    'required': ['Properties']
}