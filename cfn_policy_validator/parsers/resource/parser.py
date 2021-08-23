"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging

from cfn_policy_validator.parsers.resource.kms import KmsKeyPolicyParser
from cfn_policy_validator.parsers.resource.s3 import S3BucketPolicyParser
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

        return [policy for parser in invoked_parsers for policy in parser.get_policies()]
