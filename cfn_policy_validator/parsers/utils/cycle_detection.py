"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.application_error import ApplicationError


def validate_no_cycle(resource_name, resource_property, visited_values):
    """
    Validate that there are no recursive cycles present in CFN intrinsic functions.
    """

    node_to_check = VisitedNode(resource_name, resource_property)
    # if we've seen this node before, there must be a cycle
    if node_to_check in visited_values:
        raise ApplicationError(f'Cycle detected for {resource_name} and {resource_property}.')

    visited_values.append(node_to_check)


class VisitedNode:
    def __init__(self, resource_name, property_name):
        self.resource_name = resource_name
        self.property_name = property_name

    def __eq__(self, other):
        return isinstance(other, type(self)) \
            and (self.resource_name, self.property_name) == \
                (other.resource_name, other.property_name)

    def __hash__(self):
        return hash((self.resource_name, self.property_name))
