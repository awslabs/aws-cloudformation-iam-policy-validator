"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import re
from cfn_policy_validator.cfn_tools import regex_patterns
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_get_att_evaluator import validate_fn_get_att_schema
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_sub_evaluator import validate_fn_sub_schema


class TopologicalSorter:
    """
    Topologically sort CloudFormation resources so that we can process them in dependency order.  This allows us
    to simplify logic elsewhere by knowing that any dependencies were already processed.
    """

    def __init__(self, template):
        self.template = template
        self.resources = self.template['Resources']
        self.sorted_resources = []
        self.visited_resource_names = []

    def sort_resources(self):
        for resource_name in self.resources:
            if resource_name not in self.visited_resource_names:
                self.__inner_sort(resource_name, self.resources[resource_name])

        return self.sorted_resources

    def __inner_sort(self, resource_name, resource_value):
        self.visited_resource_names.append(resource_name)

        visitor = ResourceVisitor(resource_name, resource_value, self.resources)

        # we need to create a starting node for the crawler to perform a DFS on the tree and call ResourceVisitor
        # on each visited node
        parent = CloudFormationNode("Resources", self.resources)
        resource = CloudFormationNode(resource_name, resource_value, parent=parent, visitors=[visitor])
        resource.visit_children()

        node = visitor.get_node()

        for dependency_name in node.depends_on:
            if dependency_name not in self.visited_resource_names:
                dependent_resource_value = self.resources[dependency_name]
                self.__inner_sort(dependency_name, dependent_resource_value)

        self.sorted_resources.append(node)


class CloudFormationNode:
    def __init__(self, key, value, parent=None, ancestors=None, visitors=None):
        """
        A representation of a CloudFormation node that implements the visitor pattern
        """
        self.parent = parent

        self.ancestors = [] if ancestors is None else ancestors
        self.key = key
        self.value = value

        self.is_resource = self.parent is not None and self.parent.key == 'Resources'
        self.is_reference = self.key == "Ref"
        self.is_get_att = self.key == "Fn::GetAtt"
        self.is_sub = self.key == "Fn::Sub"

        self.__visitors = [] if visitors is None else visitors

    def visit_children(self):
        """ Visits all children of the current node and
        continues recursively for child dictionaries
        """

        for visitor in self.__visitors:
            visitor.visit(self)

        copy_of_ancestors = list(self.ancestors)
        copy_of_ancestors.append(self)

        if isinstance(self.value, dict):
            self._iterate_over_dict(self.value, copy_of_ancestors)
        elif isinstance(self.value, list):
            self._iterate_over_list(self.value, copy_of_ancestors)

    def _iterate_over_list(self, value_list, ancestors):
        for value in value_list:
            # the iterator treats items in a list as nodes with a key of None
            cfn_node = CloudFormationNode(None, value, self, ancestors, self.__visitors)
            cfn_node.visit_children()

    def _iterate_over_dict(self, dictionary, ancestors):
        for key in dictionary:
            value = dictionary[key]

            cfn_node = CloudFormationNode(key, value, self, ancestors, self.__visitors)
            cfn_node.visit_children()


class ResourceVisitor:
    def __init__(self, resource_name, resource_value, resources):
        self.dependencies = set()
        self.resource_name = resource_name
        self.resource_value = resource_value
        self.all_resources = resources

    def visit(self, cfn_node):
        if cfn_node.is_reference:
            self.__add_dependency_if_resource(cfn_node.value)

        elif cfn_node.is_get_att:
            validate_fn_get_att_schema(cfn_node.value)
            reference_name = cfn_node.value[0]
            self.__add_dependency_if_resource(reference_name)

        elif cfn_node.is_sub:
            validate_fn_sub_schema(cfn_node.value)

            if isinstance(cfn_node.value, list):
                string_to_evaluate = cfn_node.value[0]
                self.__add_fn_sub_dependencies(string_to_evaluate)
            else:
                self.__add_fn_sub_dependencies(cfn_node.value)

        elif cfn_node.is_resource:
            explicit_dependencies = cfn_node.value.get('DependsOn')
            if not isinstance(explicit_dependencies, list):
                explicit_dependencies = [explicit_dependencies]

            for dependency in explicit_dependencies:
                self.__add_dependency_if_resource(dependency)

    def __add_fn_sub_dependencies(self, value):
        matches = re.findall(regex_patterns.fn_sub_variables, value)
        for match in matches:
            if '.' in match:
                reference_name = match.split('.')[0]
                self.__add_dependency_if_resource(reference_name)
            else:
                self.__add_dependency_if_resource(match)

    def __add_dependency_if_resource(self, name):
        if name in self.all_resources:
            self.dependencies.add(name)

    def get_node(self):
        return Node(self.resource_name, self.resource_value, self.dependencies)


class Node:
    def __init__(self, logical_name, value, dependencies):
        self.logical_name = logical_name
        self.value = value
        self.depends_on = dependencies
