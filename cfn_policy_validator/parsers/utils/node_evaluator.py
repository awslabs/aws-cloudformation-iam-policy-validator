"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import functools

from cfn_policy_validator.cfn_tools.cfn_object import CfnObject
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema
from cfn_policy_validator.parsers.utils.arn_generator import ArnGenerator
from cfn_policy_validator.parsers.utils.conditions_evaluator import ConditionsEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.aws_no_value_evaluator import AwsNoValueEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.condition_function_evaluator import \
    ConditionFunctionEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.dynamic_ref_evaluator import DynamicReferenceEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_and_evaluator import AndEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_equals_evaluator import EqualsEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_find_in_map_evaluator import FindInMapEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_get_att_evaluator import GetAttEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_if_evaluator import IfEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_import_value_evaluator import ImportValueEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_join_evaluator import JoinEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_not_evaluator import NotEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_or_evaluator import OrEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_select_evaluator import SelectEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_split_evaluator import SplitEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.fn_sub_evaluator import SubEvaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.ref_evaluator import RefEvaluator

from typing import Any


def evaluate_dynamic_references(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        dynamic_reference_evaluator = args[0].dynamic_reference_evaluator
        value = func(*args, **kwargs)
        if isinstance(value, str):
            return dynamic_reference_evaluator.evaluate(value)
        else:
            return value

    return wrapper


def prune_references_to_no_value(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        no_value_evaluator = args[0].no_value_evaluator
        value = func(*args, **kwargs)
        return no_value_evaluator.evaluate(value)

    return wrapper


class NodeEvaluator:
    def __init__(self, template, account_config, parameter_values, allow_dynamic_ref_without_version: bool):
        resources = template['Resources']
        parameters = template.get('Parameters', {})
        mappings = template.get('Mappings', {})
        conditions = template.get('Conditions', {})

        arn_generator = ArnGenerator(account_config)

        self.dynamic_reference_evaluator = DynamicReferenceEvaluator(account_config.region, allow_dynamic_ref_without_version)
        self.no_value_evaluator = AwsNoValueEvaluator()

        conditions_evaluator = ConditionsEvaluator(conditions, self)
        ref_evaluator = RefEvaluator(resources, arn_generator, parameters, parameter_values, account_config, self)
        get_att_evaluator = GetAttEvaluator(resources, arn_generator, self, account_config.region)
        self.evaluators = {
            'Ref': ref_evaluator,
            'Fn::GetAtt': get_att_evaluator,
            'Fn::Sub': SubEvaluator(ref_evaluator, get_att_evaluator, self),
            'Fn::ImportValue': ImportValueEvaluator(self, account_config.region),
            'Fn::Split': SplitEvaluator(self),
            'Fn::Join': JoinEvaluator(self),
            'Fn::Select': SelectEvaluator(self),
            'Fn::FindInMap':  FindInMapEvaluator(mappings, self),
            'Fn::If': IfEvaluator(conditions_evaluator, self),
            'Fn::Equals': EqualsEvaluator(self),
            'Fn::Or': OrEvaluator(self),
            'Fn::And': AndEvaluator(self),
            'Fn::Not': NotEvaluator(self),
            'Condition': ConditionFunctionEvaluator(conditions_evaluator)
        }

    def eval_with_validation(self, value: Any, expected_schema: Any, resource_properties_to_eval=None, path: str = None, visited_nodes=None):
        value = self.eval(value, resource_properties_to_eval, visited_nodes)
        if value is not None:
            validate_schema(value, expected_schema, path)

        return value

    @prune_references_to_no_value
    @evaluate_dynamic_references
    def eval(self, value: Any, resource_properties_to_eval=None, visited_nodes=None):
        """ Evaluates the value of a CloudFormation key/value pair by evaluating intrinsic functions and pseudo
            parameters in the template and returns the evaluated value.

            value: the value of a key/value pair in a CloudFormation template
            resource_properties_to_eval: only evaluate these properties for a resource.  This limits the scope of intrinsic
                function support to be only those functions that we'd expect to exist in an IAM policy
                (e.g. Fn::GetAZs is not likely to appear)
            visited_nodes: tracks visited nodes to detect circular references in a CloudFormation template
        """
        visited_nodes = [] if visited_nodes is None else visited_nodes

        if isinstance(value, list):
            # when passing the list of visited values to child list items, we create a separate copy for each so
            # that they don't share the same visited references
            return [self.eval(item, copy.deepcopy(visited_nodes)) for item in value]

        elif isinstance(value, CfnObject):
            # intrinsic functions must be the only key, so we only need to look at the first key
            first_key = next(iter(value), None)

            # the condition function is a special case since 'condition' can appear in other places like IAM policies
            # ignore it if we're not in the "Conditions" section of the template.  longer term we should only evaluate
            # intrinsic functions in valid sections of the template
            if first_key == 'Condition' and value.top_level_ancestor != 'Conditions':
                evaluator = None
            else:
                evaluator = self.evaluators.get(first_key)

            if evaluator is not None:
                intrinsic_function_value = value.get(first_key)
                return evaluator.evaluate(intrinsic_function_value, visited_nodes=visited_nodes)

            # if it's not an intrinsic function, recursively traverse through child nodes
            for key in value.keys():
                # we only want to evaluate resource properties that we care about for IAM policies
                # if we were to evaluate all resource properties, the scope of supported intrinsic functions and
                # CFN parameters that would need to be passed would be larger.  This will ignore properties that we
                # don't care about.
                if value.parent == 'Properties':
                    if resource_properties_to_eval is not None and \
                            key not in resource_properties_to_eval:
                        continue

                # when passing the list of visited nodes to child evals, create a separate copy for each so
                # that they don't share the same visited references
                copy_of_visited_nodes = copy.deepcopy(visited_nodes)
                value[key] = self.eval(value[key], resource_properties_to_eval, copy_of_visited_nodes)

            return dict(value)

        else:
            return value
