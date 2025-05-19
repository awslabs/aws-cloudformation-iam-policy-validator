"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError
from collections import OrderedDict

# Cache for REST API attributes with a maximum size
MAX_CACHE_SIZE = 100
api_cache = OrderedDict()  # Format: {rest_api_name: {'id': 'api_id', 'rootResourceId': 'root_id'}}


# Resolution of the rest api id.
def get_rest_api_id(region, rest_api_name, resource=None):
    if rest_api_name in api_cache:
        # Move to end to mark as recently used
        api_data = api_cache.pop(rest_api_name)
        api_cache[rest_api_name] = api_data
        return api_cache[rest_api_name]['id']

    get_attributes(region, rest_api_name)
    return api_cache[rest_api_name]['id']

def get_root_resource_id(region, rest_api_name, resource=None):
    if rest_api_name in api_cache:
        # Move to end to mark as recently used
        api_data = api_cache.pop(rest_api_name)
        api_cache[rest_api_name] = api_data
        return api_cache[rest_api_name]['rootResourceId']
    
    get_attributes(region, rest_api_name)
    return api_cache[rest_api_name]['rootResourceId']
    

def get_attributes(region, rest_api_name):
    apigateway_client = client.build('apigateway', region)
    paginator = apigateway_client.get_paginator('get_rest_apis')

    pagination_config={
        'limit': 1
    }

    for page in paginator.paginate(**pagination_config):
        for item in page.get('items', []):
            if item.get('name') == rest_api_name:
                # If cache is full, remove the least recently used item
                if len(api_cache) >= MAX_CACHE_SIZE:
                    api_cache.popitem(last=False)
                
                api_cache[rest_api_name] = {
                    'id': item['id'],
                    'rootResourceId': item['rootResourceId']
                }
                return
    
    raise ApplicationError(f'No rest api found with logical name: {rest_api_name}')
