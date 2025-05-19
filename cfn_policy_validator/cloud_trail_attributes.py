"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError

def get_dashboard_created_time(region, resource_name, resource=None):
    return get_dashboard_attribute(region, resource_name, 'CreatedTimestamp')

def get_dashboard_status(region, resource_name, resource=None):
    return get_dashboard_attribute(region, resource_name, 'Status')

def get_dashboard_type(region, resource_name, resource=None):
    return get_dashboard_attribute(region, resource_name, 'Type')

def get_dashboard_updated_time(region, resource_name, resource=None):
    return get_dashboard_attribute(region, resource_name, 'UpdatedTimestamp')

def get_eventdatastore_arn(arn_pattern, resource_name, resource, visited_nodes, region):
    return get_eventdatastore_arn_from_client(region, resource_name)

def get_eventdatastore_created_time(region, resource_name, resource=None):
    return get_eventdatastore_attribute(region, resource_name, 'CreatedTimestamp')

def get_eventdatastore_status(region, resource_name, resource=None):
    return get_eventdatastore_attribute(region, resource_name, 'Status')

def get_eventdatastore_updated_time(region, resource_name, resource=None):
    return get_eventdatastore_attribute(region, resource_name, 'UpdatedTimestamp')


def get_dashboard_attribute(region, resource_name, attribute):
    supported_attributes = ['Type', 'CreatedTimestamp', 'Status', 'UpdatedTimestamp']
    cloudtrail_client = client.build('cloudtrail', region)
    try:
        if attribute not in supported_attributes:
            raise ApplicationError(f"Attribute {attribute} is not supported. Supported attributes are {supported_attributes}")
        response = cloudtrail_client.get_dashboard(
            DashboardId=resource_name
        )
        return response[attribute]
    except Exception as e:
        raise ApplicationError(f"Error: {e}")

def get_eventdatastore_arn_from_client(region, resource_name):
    cloudtrail_client = client.build('cloudtrail', region)
    next_token = None
    client_config = {
        'MaxResults': 25
    }
  
    while True:
        if next_token:
            client_config['NextToken'] = nextToken
        response = cloudtrail_client.list_event_data_stores(**client_config)
        for eventdatastore in response['EventDataStores']:
            if eventdatastore['Name'] == resource_name:
                return eventdatastore['EventDataStoreArn']
        nextToken = response.get('NextToken')
        if not nextToken:
            break
    raise ApplicationError(f"CloudTrail Event Data Store {resource_name} not found")

    
def get_eventdatastore_attribute(region, resource_name, attribute):
    cloudtrail_client = client.build('cloudtrail', region)
    supported_attributes = ['CreatedTimestamp', 'Status', 'UpdatedTimestamp']

    if attribute not in supported_attributes:
        raise ApplicationError(f"Attribute {attribute} is not supported. Supported attributes are {supported_attributes}")
    
    arn=get_eventdatastore_arn_from_client(region, resource_name)
    event_data_store_response = cloudtrail_client.get_event_data_store(EventDataStore=arn)
    ret = event_data_store_response[attribute]
    return ret
    
    