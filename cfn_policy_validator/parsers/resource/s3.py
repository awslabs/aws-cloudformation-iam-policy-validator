"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource
from cfn_policy_validator.parsers.resource import get_parser_of_type


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


class S3BucketAclParser:
    """ AWS::S3::Bucket
    """
    def __init__(self):
        self.bucket_acls = []

    def parse(self, resource_name, resource):
        evaluated_resource = resource.eval(bucket_schema)
        properties = evaluated_resource.get('Properties', {})

        access_control = properties.get('AccessControl')
        if access_control is None:
            return

        bucket_name = properties.get('BucketName', resource_name)

        policy = Policy('BucketAcl', None)
        resource = Resource(bucket_name, 'AWS::S3::Bucket', policy, configuration={'AccessControl': access_control})

        self.bucket_acls.append(resource)

    def get_policies(self):
        return self.bucket_acls

    def merge_resource(self, bucket_acl, bucket_policy):
        bucket_policy.Configuration = bucket_acl.Configuration

    def merge_policies(self, other_resource_parsers):
        # look and see if there were any s3 bucket policies parsed
        s3_bucket_policy_parser = get_parser_of_type(other_resource_parsers, S3BucketPolicyParser)
        if s3_bucket_policy_parser is None:
            return

        unmerged_bucket_acls = []

        bucket_policies = s3_bucket_policy_parser.get_policies()
        for bucket_acl in self.bucket_acls:
            matching_bucket_policy = next((bucket_policy for bucket_policy in bucket_policies
                                        if bucket_acl.ResourceName == bucket_policy.ResourceName), None)

            # if there were no matching bucket policies, there is nothing to merge
            if matching_bucket_policy is None:
                unmerged_bucket_acls.append(bucket_acl)
            else:
                # there must be exactly 1 matching bucket policy at this point and we merge the ACL and bucket
                # policy into a single resource
                self.merge_resource(bucket_acl, matching_bucket_policy)

        self.bucket_acls = unmerged_bucket_acls


bucket_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'BucketName': {
                    'type': 'string'
                },
                'AccessControl': {
                    'type': 'string'
                }
            }
        }
    }
}


class S3AccessPointPolicyParser:
    """ AWS::S3::AccessPoint
    """

    def __init__(self):
        self.access_point_policies = []

    def parse(self, resource_name, resource):
        evaluated_resource = resource.eval(access_point_policy_schema)
        properties = evaluated_resource['Properties']

        policy_document = properties.get('Policy')
        if policy_document is None:
            # we don't need to parse access points that don't have policies and policy is optional
            return

        access_point_name = properties.get('Name', resource_name)
        vpc_id = properties.get('VpcConfiguration', {}).get('VpcId')

        configuration = None
        if vpc_id is not None:
            configuration = {
                'VpcId': vpc_id
            }

        policy = Policy('AccessPointPolicy', policy_document)
        resource = Resource(access_point_name, 'AWS::S3::AccessPoint', policy, configuration)

        self.access_point_policies.append(resource)

    def get_policies(self):
        return self.access_point_policies


access_point_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'Name': {
                    'type': 'string'
                },
                'Policy': {
                    'type': 'object'
                },
                'VpcConfiguration': {
                    'type': 'object'
                }
            }
        }
    },
    'required': ['Properties']
}


class S3MultiRegionAccessPointPolicyParser:
    """ AWS::S3::MultiRegionAccessPointPolicy
    """

    def __init__(self):
        self.multi_region_access_point_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(multi_region_access_point_policy_schema)
        properties = evaluated_resource['Properties']

        mrap_name = properties['MrapName']
        policy = properties['Policy']

        policy_document = Policy('MultiRegionAccessPointPolicy', policy)
        resource = Resource(mrap_name, 'AWS::S3::MultiRegionAccessPoint', policy_document)

        self.multi_region_access_point_policies.append(resource)

    def get_policies(self):
        return self.multi_region_access_point_policies


multi_region_access_point_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'MrapName': {
                    'type': 'string'
                },
                'Policy': {
                    'type': 'object'
                }
            },
            'required': ['MrapName', 'Policy']
        }
    },
    'required': ['Properties']
}
