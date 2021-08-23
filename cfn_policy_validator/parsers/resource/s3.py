"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.parsers.output import Policy, Resource


class S3BucketPolicyParser:
    """ AWS::S3::BucketPolicy
    """

    def __init__(self):
        self.bucket_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(bucket_policy_schema)
        properties = evaluated_resource['Properties']

        bucket_name = properties['Bucket']
        policy_document = properties['PolicyDocument']

        policy = Policy('BucketPolicy', policy_document)
        resource = Resource(bucket_name, 'AWS::S3::Bucket', policy)

        self.bucket_policies.append(resource)

    def get_policies(self):
        return self.bucket_policies


bucket_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'Bucket': {
                    'type': 'string'
                },
                'PolicyDocument': {
                    'type': 'object'
                }
            },
            'required': ['Bucket', 'PolicyDocument']
        }
    },
    'required': ['Properties']
}