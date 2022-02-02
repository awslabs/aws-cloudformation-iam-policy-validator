"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging

from cfn_policy_validator.parsers.resource.kms import KmsKeyPolicyParser
from cfn_policy_validator.parsers.resource.s3 import S3BucketPolicyParser, S3AccessPointPolicyParser, \
    S3MultiRegionAccessPointPolicyParser, S3BucketAclParser
from cfn_policy_validator.parsers.resource.sns import SnsTopicPolicyParser
from cfn_policy_validator.parsers.resource.sqs import SqsQueuePolicyParser
from cfn_policy_validator.parsers.resource.lambda_aws import LambdaPermissionPolicyParser, LambdaLayerVersionPermissionParser
from cfn_policy_validator.parsers.resource.secrets_manager import SecretsManagerPolicyParser

from cfn_policy_validator.parsers.utils.topological_sorter import TopologicalSorter


LOGGER = logging.getLogger("cfn-policy-validator")


class ResourceParser:
    """
    Passes parsing for resource-based policies to resource-specific parsers.  To add a new parser, modify the parsers
    dictionary below.
    """

    @classmethod
    def parse(cls, template, account_config):
        # topologically sort which allows us to process dependent resources first
        sorter = TopologicalSorter(template)
        sorted_resources = sorter.sort_resources()

        parsers = {
            'AWS::S3::AccessPoint': S3AccessPointPolicyParser(),
            'AWS::S3::MultiRegionAccessPointPolicy': S3MultiRegionAccessPointPolicyParser(),
            'AWS::S3::Bucket': S3BucketAclParser(),
            'AWS::S3::BucketPolicy': S3BucketPolicyParser(),
            'AWS::SQS::QueuePolicy': SqsQueuePolicyParser(),
            'AWS::SNS::TopicPolicy': SnsTopicPolicyParser(),
            'AWS::KMS::Key': KmsKeyPolicyParser(),
            'AWS::Lambda::Permission': LambdaPermissionPolicyParser(account_config),
            'AWS::Lambda::LayerVersionPermission': LambdaLayerVersionPermissionParser(account_config.partition),
            'AWS::SecretsManager::ResourcePolicy': SecretsManagerPolicyParser()
        }

        invoked_parsers = set()
        for resource in sorted_resources:
            resource_type = resource.value['Type']
            parser = parsers.get(resource_type)
            if parser is not None:
                LOGGER.info(f'Parsing resource type {resource_type} with logical name {resource.logical_name}..')
                parser.parse(resource.logical_name, resource.value)
                invoked_parsers.add(parser)

        # If multiple cfn resource types exist in the same template that should be validated together, combine them
        # into a single resource as it may be confusing to validate the same resource twice.
        # an example is if an AWS::S3::Bucket is defined with ACLs and also has an AWS::S3::BucketPolicy.
        # If they are in different templates, it's OK to evaluate them separately
        for parser in invoked_parsers:
            merge_policies = getattr(parser, "merge_policies", None)
            if merge_policies is not None:
                parser.merge_policies(invoked_parsers)

        return [policy for parser in invoked_parsers for policy in parser.get_policies()]
