"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from typing import TextIO

import json
import yaml

from cfn_policy_validator.cfn_tools import schema_validator
from cfn_policy_validator.cfn_tools.cfn_object import CfnObject
from cfn_policy_validator.cfn_tools.yaml_loader import CfnYamlLoader
from cfn_policy_validator.parsers.account_config import AccountConfig
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator


def load(stream: TextIO, account_config: AccountConfig, parameters: dict):
	raw_template = stream.read()
	try:
		template = json.loads(raw_template, object_hook=CfnObject)
	except ValueError:
		template = yaml.load(raw_template, Loader=CfnYamlLoader)

	schema_validator.validate(template)
	node_evaluator = NodeEvaluator(template, account_config, parameters)
	_populate_cfn_object(template, node_evaluator, [])
	return template


def _populate_cfn_object(d, node_evaluator, ancestors, parent=None):
	# recurse into a custom data structure that represents a node in the template
	if isinstance(d, CfnObject):
		d.add_ancestors(ancestors, parent)
		d.set_node_evaluator(node_evaluator)
		for key, value in d.items():
			_populate_cfn_object(value, node_evaluator, d.ancestors, key)
	elif isinstance(d, list):
		for item in d:
			_populate_cfn_object(item, node_evaluator, ancestors, parent)
