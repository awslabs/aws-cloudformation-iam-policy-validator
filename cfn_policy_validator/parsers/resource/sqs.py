"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from urllib.parse import urlparse

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.output import Policy, Resource


class SqsQueuePolicyParser:
    """ AWS::SQS::QueuePolicy
    """
    def __init__(self):
        self.queue_policies = []

    def parse(self, _, resource):
        evaluated_resource = resource.eval(sqs_queue_policy_schema)
        properties = evaluated_resource['Properties']

        queue_urls = properties['Queues']
        policy_document = properties['PolicyDocument']

        for queue in queue_urls:
            parsed_url = urlparse(queue)
            try:
                queue_name = parsed_url.path.split('/')[2]
            except IndexError:
                raise ApplicationError(f'Invalid queue URL. Unable to parse name from URL. Invalid value: "{queue}"')

            policy = Policy('QueuePolicy', policy_document)
            resource = Resource(queue_name, 'AWS::SQS::Queue', policy)

            self.queue_policies.append(resource)

    def get_policies(self):
        return self.queue_policies


sqs_queue_policy_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'PolicyDocument': {
                    'type': 'object'
                },
                'Queues': {
                    'type': 'array',
                    'minItems': 1,
                    'items': {
                        'type': 'string'
                    }
                }
            },
            'required': ['PolicyDocument', 'Queues']
        }
    },
    'required': ['Properties']
}
