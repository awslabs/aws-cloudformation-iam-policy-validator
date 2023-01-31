"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import io
import json
import sys
import warnings

from contextlib import contextmanager
from io import StringIO

from cfn_policy_validator.cfn_tools import cfn_loader
from cfn_policy_validator.tests import account_config, default_get_latest_ssm_parameter_version


def load(template, parameters={}):
    stream = io.StringIO(json.dumps(template))
    return cfn_loader.load(stream, account_config, default_get_latest_ssm_parameter_version, parameters)


def load_resources(resources):
    template = {
        'Resources': resources
    }
    return load(template)


def required_property_error(key, path):
    return f"'{key}' is a required property, Path: {path}"


def expected_type_error(path: str, expected_type: str, actual_value: str):
    return f"{actual_value} is not of type '{expected_type}', Path: {path}"


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


def ignore_warnings():
    warnings.simplefilter("ignore", ResourceWarning)


def raw_diff(policy_1, policy_2):
    __iterate_over_dict(policy_1, policy_2)


def diff(policy, resources, resource_index):
    raw_diff(policy.Policy, resources[resource_index].Policies[0].Policy)


def __iterate_over(key, value1, value2):
    if isinstance(value1, dict) and isinstance(value2, dict):
        __iterate_over_dict(value1, value2)
    elif isinstance(value1, list) and isinstance(value2, list):
        __iterate_over_list(key, value1, value2)
    else:
        if type(value1) != type(value2):
            print(f'Different types for key {key}')
            print(f'1: {value1}, 2: {value2}')
        elif value1 != value2:
            print(f'Values for {key} differ: {value1} - {value2}')


def __iterate_over_list(key, value_list1, value_list2):
    if len(value_list1) != len(value_list2):
        print(f'Lists with key {key} have different lengths.')

    for index, value in enumerate(value_list1):
        if index > len(value_list2):
            continue

        value2 = value_list2[index]
        __iterate_over(key, value, value2)


def __iterate_over_dict(dict1, dict2):
    for key, value in dict2.items():
        self_key = dict1.get(key)
        if self_key is None:
            print(f'{key} in policy 2, not in policy 1')

    for key, value in dict1.items():
        other_key = dict2.get(key)
        if other_key is None:
            print(f'{key} in policy 1, not in policy 2 ')
        else:
            __iterate_over(key, dict1[key], dict2[key])