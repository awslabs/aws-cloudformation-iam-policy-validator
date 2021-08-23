"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.parsers.output import Policy, Resource


class SnsTopicPolicyParser:
    """ AWS::SNS::TopicPolicy
    """
    def __init__(self):
        self.topic_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(sns_topic_policy_schema)
        properties = evaluated_resource['Properties']

        topic_arns = properties['Topics']
        policy_document = properties['PolicyDocument']

        for topic_arn in topic_arns:
            topic_name = topic_arn.split(':')[-1]

            policy = Policy('TopicPolicy', policy_document)
            resource = Resource(topic_name, 'AWS::SNS::Topic', policy)

            self.topic_policies.append(resource)

    def get_policies(self):
        return self.topic_policies


sns_topic_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'PolicyDocument': {
                    'type': 'object'
                },
                'Topics': {
                    'type': 'array',
                    'minItems': 1,
                    'items': {
                        'type': 'string'
                    }
                }
            },
            'required': ['PolicyDocument', 'Topics']
        }
    },
    'required': ['Properties']
}