"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os
import re

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.arn_generator_schemas import iam_role_schema, iam_user_schema, \
    elbv2_load_balancer_schema, elbv2_listener_schema, elbv2_target_group_schema, network_firewall_rulegroup_schema


class ArnGenerator:
    """
    This class uses the cfn_to_arn_map.json file to automatically generate valid ARNs from a CloudFormation resource
    type.  It does this by replacing variables from the arn patterns in the cfn_to_arn_map.json file.  An arn pattern
    looks like this: arn:${Partition}:sqs:${Region}:${Account}:${QueueName}

    Any variable within ${..} and not named Partition, Region, or Account is replaced with the resource name.  This
    works because IAM policy validation does not rely on the name of the resource.
    """

    def __init__(self, account_config):
        this_files_directory = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(this_files_directory, 'cfn_to_arn_map.json')) as f:
            self.cfn_to_arn_map = json.load(f)

        self.account_config = account_config

        # some ARN generation requires custom logic (e.g. an ELB can have 2 different ARNs depending on the ELB type)
        self.custom_generators = {
            'AWS::ElasticLoadBalancingV2::LoadBalancer': generate_elbv2_load_balancer_arn,
            'AWS::ElasticLoadBalancingV2::Listener': generate_elbv2_listener_arn,
            'AWS::ElasticLoadBalancingV2::TargetGroup': generate_elbv2_target_group_arn,
            'AWS::IAM::Role': generate_role_arn,
            'AWS::IAM::User': generate_user_arn,
            'AWS::NetworkFirewall::RuleGroup': generate_network_firewall_rule_group
        }

    def try_generate_arn(self, resource_name, resource, attribute_or_ref, visited_values=None):
        if visited_values is None:
            visited_values = []

        cfn_type = resource['Type']
        split_cfn_type = cfn_type.split("::")
        if len(split_cfn_type) != 3:
            if len(split_cfn_type) == 4 and split_cfn_type[3].lower() == 'module':
                raise ApplicationError(f'Unable to resolve {cfn_type}. CloudFormation modules are not yet supported.')

            raise ApplicationError(f'Invalid resource type: {cfn_type}')

        service_name = split_cfn_type[1]
        resource_type = split_cfn_type[2]

        arn_pattern = self.cfn_to_arn_map\
            .get(service_name, {})\
            .get(resource_type, {})\
            .get(attribute_or_ref)

        if arn_pattern is None:
            return None

        arn_pattern = arn_pattern['Value']

        # arn_patterns follow the format: arn:${Partition}:sqs:${Region}:${Account}:${QueueName}
        # where Partition, Account, and Region are standardized variable names
        arn_pattern = arn_pattern.replace("${Partition}", self.account_config.partition)
        arn_pattern = arn_pattern.replace("${Region}", self.account_config.region)
        arn_pattern = arn_pattern.replace("${Account}", self.account_config.account_id)

        # certain CFN types require some additional generation that is specific to the resource type
        # for example, we include the exact path with any roles or users, ALBs and NLBs share the same cfn resource,
        # but have different ARNs
        custom_generator = self.custom_generators.get(cfn_type)
        if custom_generator is not None:
            arn_pattern = custom_generator(arn_pattern, resource_name, resource, visited_values)

        # match any variable (anything not Partition, Account, Region) within brackets and replace with the resource name
        # e.g. arn:aws:..:${SomeResourceName} -> arn:aws:..:ResourceName
        regex = r"(?P<Variable>\${[^}]*})"

        def callback(match):
            return resource_name

        arn_pattern = re.sub(regex, callback, arn_pattern)

        return arn_pattern


# AWS::IAM::Role
# include the path in the Role ARN which will be helpful for analysis
def generate_role_arn(arn_pattern, resource_name, resource, visited_values):
    evaluated_resource = resource.eval(iam_role_schema, visited_values)

    properties = evaluated_resource['Properties']

    path = properties.get('Path', '/')
    # remove the leading / to fit the template
    path = path[1:]

    name = properties.get('RoleName', resource_name)

    return arn_pattern.replace("${RoleNameWithPath}", path + name)


# AWS::IAM::User
# include the path in the User ARN which will be helpful for analysis
def generate_user_arn(arn_pattern, resource_name, resource, visited_values):
    evaluated_resource = resource.eval(iam_user_schema, visited_values)

    properties = evaluated_resource.get('Properties', {})

    path = properties.get('Path', '/')
    # remove the leading / to fit the template
    path = path[1:]

    name = properties.get('UserName', resource_name)
    return arn_pattern.replace("${UserNameWithPath}", path + name)


# Multiple load balancers share the same CFN resources, but have different ARNs depending on load balancer type
# AWS::ElasticLoadBalancingV2::LoadBalancer
def generate_elbv2_load_balancer_arn(arn_pattern, _, resource, visited_values):
    evaluated_resource = resource.eval(elbv2_load_balancer_schema, visited_values)
    properties = evaluated_resource.get('Properties', {})

    lb_type = properties.get('Type')
    if lb_type is None:
        lb_type = 'application'

    if lb_type == 'network':
        return arn_pattern.replace('loadbalancer/app/', 'loadbalancer/net/')
    elif lb_type == 'gateway':
        return arn_pattern.replace('loadbalancer/app/', 'loadbalancer/gwy/')

    return arn_pattern


# AWS::ElasticLoadBalancingV2::Listener
def generate_elbv2_listener_arn(arn_pattern, _, resource, visited_values):
    evaluated_resource = resource.eval(elbv2_listener_schema, visited_values)

    properties = evaluated_resource['Properties']
    protocol = properties.get('Protocol')

    if protocol is None:
        return arn_pattern.replace('listener/app/', 'listener/gwy/')

    if protocol not in ['HTTP', 'HTTPS']:
        return arn_pattern.replace('listener/app/', 'listener/net/')

    return arn_pattern


# AWS::ElasticLoadBalancingV2::TargetGroup
def generate_elbv2_target_group_arn(arn_pattern, _, resource, visited_values):
    evaluated_resource = resource.eval(elbv2_target_group_schema, visited_values)

    properties = evaluated_resource.get('Properties', {})
    protocol = properties.get('Protocol')

    if protocol is None:
        return arn_pattern

    if protocol == 'GENEVE':
        return arn_pattern.replace('loadbalancer/app/', 'loadbalancer/gwy/')

    if protocol in ['HTTP', 'HTTPS']:
        return arn_pattern

    return arn_pattern.replace('loadbalancer/app/', 'loadbalancer/net/')


# AWS::NetworkFirewall::RuleGroup
# network firewall rule groups can be either stateful or stateless and have different ARNs depending on the type
def generate_network_firewall_rule_group(arn_pattern, _, resource, visited_values):
    evaluated_resource = resource.eval(network_firewall_rulegroup_schema, visited_values)

    properties = evaluated_resource['Properties']
    rule_group_type = properties['Type']

    if rule_group_type == 'STATEFUL':
        return arn_pattern

    return arn_pattern.replace(':stateful-rulegroup/', ':stateless-rulegroup/')
