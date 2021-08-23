"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import itertools

from collections import defaultdict
from cfn_policy_validator.parsers.output import Policy, Resource


class LambdaPermissionPolicyParser:
    """ AWS::Lambda::Permission
    """
    def __init__(self, account_config):
        self.partition = account_config.partition
        self.region = account_config.region
        self.account_id = account_config.account_id

        self.permissions_policies = defaultdict(list)

    def parse(self, _, resource):
        evaluated_resource = resource.eval(lambda_permission_schema)

        properties = evaluated_resource['Properties']
        action = properties['Action']
        function_name = properties['FunctionName']
        principal_name = properties['Principal']

        source_account = properties.get('SourceAccount')
        source_arn = properties.get('SourceArn')

        policy_statement = {
            'Effect': 'Allow',
            'Action': action
        }

        if 'amazonaws' in principal_name:
            # this is a permission to a service
            policy_statement['Principal'] = {'Service': principal_name}
        else:
            # otherwise this is a permission to an account
            policy_statement['Principal'] = {'AWS': principal_name}

        # function name can be a full ARN, a partial ARN (a full suffix of an ARN) or the actual function name
        if function_name.startswith('arn:'):  # full ARN
            policy_statement['Resource'] = function_name
        elif 'function:' in function_name:  # partial ARN
            # partial arn must include at least function: and ":" is not a valid function name character
            arn_parts = function_name.split(":")
            # grab all parts of the partial ARN up until "function:"
            parts_before_function = list(itertools.takewhile(lambda part: part.lower() != 'function', arn_parts))

            # a list of a valid ARN before "function:"
            valid_arn_parts_before_function = ["arn", self.partition, "lambda", self.region, self.account_id]

            # construct the base_arn based on what's missing in the partial ARN
            number_of_missing_arn_parts = len(valid_arn_parts_before_function) - len(parts_before_function)
            base_arn = ":".join(valid_arn_parts_before_function[:number_of_missing_arn_parts])

            policy_statement['Resource'] = f'{base_arn}:{function_name}'
        else:  # just the function name
            policy_statement['Resource'] = f'arn:{self.partition}:lambda:{self.region}:{self.account_id}:function:{function_name}'

        if source_account is not None:
            policy_statement['Condition'] = {'StringEquals': {'AWS:SourceAccount': source_account}}

        if source_arn is not None:
            condition = policy_statement.get('Condition', {})
            condition['ArnLike'] = {'AWS:SourceArn': source_arn}
            policy_statement['Condition'] = condition

        # The permissions policies dictionary holds the statements per lambda function.  The statements are built
        # into an actual policy when they are retrieved.
        function_arn = policy_statement['Resource']
        statements = self.permissions_policies[function_arn]
        statements.append(policy_statement)

    def get_policies(self):
        resources = []
        for function_arn, statements in self.permissions_policies.items():
            function_name = self.__get_function_name_from_arn(function_arn)

            policy_document = {
                'Version': '2012-10-17',
                'Statement': statements
            }
            policy = Policy('PermissionsPolicy', policy_document)
            resource = Resource(function_name, "AWS::Lambda::Function", policy)
            resources.append(resource)

        return resources

    @staticmethod
    def __get_function_name_from_arn(arn_or_partial_arn):
        split_arn = arn_or_partial_arn.split(':')
        index_of_function = split_arn.index('function')
        return split_arn[index_of_function + 1]


lambda_permission_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'Action': {
                    'type': 'string'
                },
                'FunctionName': {
                    'type': 'string'
                },
                'Principal': {
                    'type': 'string'
                },
                'SourceAccount': {
                    'type': 'string'
                },
                'SourceArn': {
                    'type': 'string'
                }
            },
            'required': ['Action', 'FunctionName', 'Principal']
        }
    },
    'required': ['Properties']
}


class LambdaLayerVersionPermissionParser:
    def __init__(self, partition):
        self.partition = partition
        self.permissions_policies = defaultdict(list)

    def parse(self, _, resource):
        evaulated_resources = resource.eval(lambda_layer_version_permission_schema)

        properties = evaulated_resources['Properties']

        action = properties['Action']
        layer_version_arn = properties['LayerVersionArn']
        principal = properties['Principal']
        organization_id = properties.get('OrganizationId')

        policy_statement = {
            'Effect': 'Allow',
            'Action': action,
            'Resource': layer_version_arn,
            'Principal': {'AWS': principal}
        }

        if organization_id is not None:
            policy_statement['Condition'] = {'StringEquals': {'aws:PrincipalOrgID': organization_id}}

        # The permissions policies dictionary holds the statements per lambda layer.  The statements are built
        # into an actual policy when they are retrieved.
        statements = self.permissions_policies[layer_version_arn]
        statements.append(policy_statement)

    def get_policies(self):
        resources = []
        for layer_version_arn, statements in self.permissions_policies.items():
            layer_name = self.__get_layer_name_from_arn(layer_version_arn)
            policy_document = {
                'Version': '2012-10-17',
                'Statement': statements
            }
            policy = Policy('LayerVersionPermission', policy_document)
            resource = Resource(layer_name, "AWS::Lambda::LayerVersion", policy)
            resources.append(resource)

        return resources

    @staticmethod
    def __get_layer_name_from_arn(arn_or_partial_arn):
        split_arn = arn_or_partial_arn.split(':')
        index_of_function = split_arn.index('layer')
        name_and_version = split_arn[index_of_function + 1:]
        return ":".join(name_and_version)


lambda_layer_version_permission_schema = {
    'type': 'object',
    'properties': {
        'Properties': {
            'type': 'object',
            'properties': {
                'Action': {
                    'type': 'string'
                },
                'LayerVersionArn': {
                    'type': 'string'
                },
                'Principal': {
                    'type': 'string'
                },
                'OrganizationId': {
                    'type': 'string'
                }
            },
            'required': ['Action', 'LayerVersionArn', 'Principal']
        }
    },
    'required': ['Properties']
}
