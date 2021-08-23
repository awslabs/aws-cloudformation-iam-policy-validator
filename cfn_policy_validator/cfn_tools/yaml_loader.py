"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import yaml

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.cfn_object import CfnObject


TAG_MAP = "tag:yaml.org,2002:map"
TAG_TIMESTAMP = "tag:yaml.org,2002:timestamp"
UNCONVERTED_SUFFIXES = ["Ref", "Condition"]
FN_PREFIX = "Fn::"


class CfnYamlLoader(yaml.SafeLoader):
    def multi_constructor(self, tag_suffix, node):
        if tag_suffix not in UNCONVERTED_SUFFIXES:
            tag_suffix = "{}{}".format(FN_PREFIX, tag_suffix)

        if tag_suffix == "Fn::GetAtt":
            constructor = self.construct_getatt
        elif isinstance(node, yaml.ScalarNode):
            constructor = self.construct_scalar
        elif isinstance(node, yaml.SequenceNode):
            constructor = self.construct_sequence
        elif isinstance(node, yaml.MappingNode):
            constructor = self.construct_mapping
        else:
            raise Exception("Bad tag: !{}".format(tag_suffix))

        return CfnObject((
            (tag_suffix, constructor(node)),
        ))

    def construct_getatt(self, node):
        if isinstance(node.value, str):
            return node.value.split(".", 1)
        if isinstance(node.value, list):
            return [s.value for s in node.value]
        else:
            raise ApplicationError("Unexpected node type: {}".format(type(node.value)))

    def construct_mapping(self, node, deep=False):
        mapping = CfnObject()

        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            value = self.construct_object(value_node, deep=deep)

            mapping[key] = value

        return mapping

    # for consistency with JSON parsing, parse datetime to string
    # must include self as first argument
    # noinspection PyMethodMayBeStatic
    def parse_datetime(self, node):
        return node.value


CfnYamlLoader.add_constructor(TAG_MAP, CfnYamlLoader.construct_mapping)
CfnYamlLoader.add_constructor(TAG_TIMESTAMP, CfnYamlLoader.parse_datetime)
CfnYamlLoader.add_multi_constructor("!", CfnYamlLoader.multi_constructor)
