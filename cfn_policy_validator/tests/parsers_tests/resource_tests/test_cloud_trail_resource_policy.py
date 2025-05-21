"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest
from datetime import datetime

from cfn_policy_validator import client
from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.tests.boto_mocks import BotoResponse, get_test_mode

dashboard_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'cloudtrail:StartDashboardRefresh',
            'Resource': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyTestDashboard',
            'Principal': '*',
            'Condition': {
                'ArnEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::971691587463:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}


dashboard_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'cloudtrail:StartDashboardRefresh',
            'Resource': [
                {"Fn::GetAtt": ["MyDashboard", "DashboardArn"]},
                {"Fn::Sub": 'arn:aws:cloudtrail::${AWS::AccountId}:dashboard/${MyDashboard}'}
            ],
            'Principal': '*',
            'Condition': {
                'StringEquals': {
                    'aws:ResourceTag/DashboardStatus': {'Fn::GetAtt': ['MyDashboard', 'Status']},
                    'aws:ResourceTag/DashboardType': {'Fn::GetAtt': ['MyDashboard', 'Type']}
                },
                'DateGreaterThanEquals': {
                    'aws:TokenIssueTime': {'Fn::GetAtt': ['MyDashboard', 'CreatedTimestamp']}
                },
                'DateLessThanEquals': {
                    'aws:TokenIssueTime': {'Fn::GetAtt': ['MyDashboard', 'UpdatedTimestamp']}
                }
            }
        }
    ]
}


eventdatastore_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': [
                'cloudtrail:StartQuery',
                'cloudtrail:GetQueryResults'
            ],
            'Resource': 'arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/MyTestEventDataStore',
            'Principal': '*',
            'Condition': {
                'ArnEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::971691587463:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}

eventdatastore_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'cloudtrail:StartQuery',
            'Resource': [
                {"Fn::GetAtt": ["MyEventDataStore", "EventDataStoreArn"]}
            ],
            'Principal': '*',
            'Condition': {
                'StringEquals': {
                    "aws:ResourceTag/EventDataStoreStatus": [
                        {'Fn::GetAtt': ['MyEventDataStore', 'Status']}
                    ]
                },
                'DateGreaterThanEquals': {
                    "aws:TokenIssueTime": [
                        {'Fn::GetAtt': ['MyEventDataStore', 'CreatedTimestamp']}
                    ]
                },
                'DateLessThanEquals': {
                    "aws:TokenIssueTime": [
                        {'Fn::GetAtt': ['MyEventDataStore', 'UpdatedTimestamp']}
                    ]
                }
            }
        }
    ]
}


class WhenParsingACloudTrailResourcePolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_resource_arn(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::CloudTrail::ResourcePolicy',
                    'Properties': {
                        'ResourcePolicy': copy.deepcopy(dashboard_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('ResourceArn', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_resource_arn_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': ['arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard'],
                    'ResourcePolicy': copy.deepcopy(dashboard_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ResourceArn', 'string', "['arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_resource_policy(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard'
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('ResourcePolicy', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_resource_policy_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard',
                    'ResourcePolicy': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.ResourcePolicy', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard',
                    'ResourcePolicy': copy.deepcopy(dashboard_policy_with_no_reference),
                    'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')

    @mock_node_evaluator_setup()
    def test_with_ref_to_parameter_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard',
                    'ResourcePolicy': copy.deepcopy(dashboard_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingACloudTrailDashboardPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::CloudTrail::ResourcePolicy',
                    'Properties': {
                        'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:dashboard/MyDashboard',
                        'ResourcePolicy': copy.deepcopy(dashboard_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyDashboard", resource.ResourceName)
        self.assertEqual('AWS::CloudTrail::Dashboard', resource.ResourceType)

        self.assertEqual('ResourcePolicy', resource.Policy.Name)
        self.assertEqual(dashboard_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingACloudTrailPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a dashboard
    import random

    dashboardCreatedTimestamp = datetime(2025, 5, 15, 0, 27, 21, 914000)
    dashboardUpdatedTimestamp = datetime(2025, 5, 15, 5, 0, 2, 184000)
    dashboardType = 'CUSTOM'
    dashboardStatus = 'UPDATED'
    dashboardARN = f'arn:aws:cloudtrail:{account_config.region}:{account_config.account_id}:dashboard/MyCustomDashboardName'

    eventStoreRandNum = random.randint(1, 100)
    eventDataStoreName = 'MyCustomEventDataStoreName-' + str(eventStoreRandNum)
    eventStoreCreatedTimestamp = datetime(2025, 5, 15, 0, 27, 21, 914000)
    eventStoreStatus = 'ENABLED'
    eventStoreUpdatedTimestamp = datetime(2025, 5, 15, 5, 0, 2, 184000)
    eventStoreId = 'ba4c2eed-6713-40cc-8fae-a7b2fb05897f'
    eventStoreArn = f'arn:aws:cloudtrail:{account_config.region}:{account_config.account_id}:eventdatastore/{eventStoreId}'
    
    @classmethod
    def setUpClass(cls):
        if get_test_mode() == "OFFLINE":
            return
        cls.dashboard_created = False
        cls.eventstore_created = False
        try:
            cloud_trail_client = client.build('cloudtrail', account_config.region)
            
            # Create an EventDataStore
            response = cloud_trail_client.create_event_data_store(
                Name=cls.eventDataStoreName,
                TerminationProtectionEnabled=False)
            cls.eventStoreArn = response['EventDataStoreArn']
            cls.eventStoreId = response['EventDataStoreArn'].split('/')[-1]
            cls.eventStoreCreatedTimestamp = response['CreatedTimestamp']
            cls.eventStoreUpdatedTimestamp = response['UpdatedTimestamp']
            cls.eventStoreStatus = response['Status']
            cls.eventstore_created = True
            print(f'Created EventDataStore with the following attributes: Name: {cls.eventDataStoreName}, EventDataStoreARN: {cls.eventStoreArn}'+
                        f'EventDataStoreId: {cls.eventStoreId}, EventDataStoreStatus: {cls.eventStoreStatus}, CreatedTimeStamp: {cls.eventStoreCreatedTimestamp}' +
                        f'UpdatedTimeStamp: {cls.eventStoreUpdatedTimestamp}'
                        )
            
            # Create a Dashboard
            response = cloud_trail_client.create_dashboard(
                Name='MyCustomDashboardName', 
                TerminationProtectionEnabled=False)
            cls.dashboardARN = response['DashboardArn']
            cls.dashboardType = response['Type']
            response = cloud_trail_client.get_dashboard(
                DashboardId='MyCustomDashboardName')
            cls.dashboardStatus = response['Status']
            cls.dashboardCreatedTimestamp = response['CreatedTimestamp']
            cls.dashboardUpdatedTimestamp = response['UpdatedTimestamp']
            cls.dashboard_created = True
            print(f'Created Dashboard with the following attributes: DashboardARN: {cls.dashboardARN}'+
                        f'DashboardStatus: {cls.dashboardStatus}, CreatedTimeStamp: {cls.dashboardCreatedTimestamp}' +
                        f'UpdatedTimeStamp: {cls.dashboardUpdatedTimestamp}'
                        )
        except Exception as e:
            print(f"Error in setUpClass: {str(e)}")
            # Let the exception propagate after we've recorded what was created
            raise
    @classmethod
    def tearDownClass(cls):
        if get_test_mode() == "OFFLINE":
            return
        cloud_trail_client = client.build('cloudtrail', account_config.region)
        if hasattr(cls, 'dashboard_created') and cls.dashboard_created:
            try:
                # Clean up the Dashboard
                cloud_trail_client.delete_dashboard(
                    DashboardId='MyCustomDashboardName')
                print(f'Cleaned up Dashboard: MyCustomDashboardName')
            except Exception as e:
                print(f"Error deleting dashboard: {str(e)}")
        
        if hasattr(cls, 'eventstore_created') and cls.eventstore_created and cls.eventStoreArn:
            try:
                # Clean up the EventDataStore
                cloud_trail_client.delete_event_data_store(
                    EventDataStore=cls.eventStoreArn)
                print(f'Cleaned up EventDataStore: {cls.eventDataStoreName}')
            except Exception as e:
                print(f"Error deleting event data store: {str(e)}")

    @mock_node_evaluator_setup(
        cloudtrail=[
            BotoResponse(
                method='get_dashboard',
                service_response= {
                    'DashboardArn': dashboardARN,
                    'Type': dashboardType,
                    'Status': dashboardStatus,
                    'CreatedTimestamp': dashboardCreatedTimestamp,
                    'UpdatedTimestamp': dashboardUpdatedTimestamp
                },
                expected_params={
                    'DashboardId': 'MyCustomDashboardName'
                }
            ),
            BotoResponse(
                method='get_dashboard',
                service_response= {
                    'DashboardArn': dashboardARN,
                    'Type': dashboardType,
                    'Status': dashboardStatus,
                    'CreatedTimestamp': dashboardCreatedTimestamp,
                    'UpdatedTimestamp': dashboardUpdatedTimestamp
                },
                expected_params={
                    'DashboardId': 'MyCustomDashboardName'
                }
            ),
            BotoResponse(
                method='get_dashboard',
                service_response= {
                    'DashboardArn': dashboardARN,
                    'Type': dashboardType,
                    'Status': dashboardStatus,
                    'CreatedTimestamp': dashboardCreatedTimestamp,
                    'UpdatedTimestamp': dashboardUpdatedTimestamp
                },
                expected_params={
                    'DashboardId': 'MyCustomDashboardName'
                }
            ),
            BotoResponse(
                method='get_dashboard',
                service_response= {
                    'DashboardArn': dashboardARN,
                    'Type': dashboardType,
                    'Status': dashboardStatus,
                    'CreatedTimestamp': dashboardCreatedTimestamp,
                    'UpdatedTimestamp': dashboardUpdatedTimestamp
                },
                expected_params={
                    'DashboardId': 'MyCustomDashboardName'
                }
            )
        ]

    )
    def test_returns_a_dashboard_resource_with_references_resolved(self):
        template = load_resources({
            'MyDashboard': {
                'Type': 'AWS::CloudTrail::Dashboard',
                'Properties': {
                    'Name': 'MyCustomDashboardName'
                }
            },
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': {'Fn::GetAtt': ['MyDashboard', 'DashboardArn']},
                    'ResourcePolicy': copy.deepcopy(dashboard_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyCustomDashboardName", resource.ResourceName)
        self.assertEqual('AWS::CloudTrail::Dashboard', resource.ResourceType)

        expected_policy = copy.deepcopy(dashboard_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:cloudtrail:{account_config.region}:{account_config.account_id}:dashboard/MyCustomDashboardName',
            f'arn:aws:cloudtrail::{account_config.account_id}:dashboard/MyCustomDashboardName'
        ]
        expected_policy['Statement'][0]['Condition']['StringEquals'] = {
            'aws:ResourceTag/DashboardStatus': self.dashboardStatus,
            'aws:ResourceTag/DashboardType': self.dashboardType
        }
        expected_policy['Statement'][0]['Condition']['DateGreaterThanEquals'] = {
            'aws:TokenIssueTime': self.dashboardCreatedTimestamp
        }
        expected_policy['Statement'][0]['Condition']['DateLessThanEquals'] = {
            'aws:TokenIssueTime': self.dashboardUpdatedTimestamp
        }
        self.assertEqual('ResourcePolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)
    

    @mock_node_evaluator_setup(
        cloudtrail=[
            BotoResponse(
                method='list_event_data_stores',
                service_response= {
                    'EventDataStores': [
                        {
                            'EventDataStoreArn': eventStoreArn,
                            'Name': eventDataStoreName
                        }
                    ]
                },
                expected_params=None
            ),
            BotoResponse(
                method='list_event_data_stores',
                service_response= {
                    'EventDataStores': [
                        {
                            'EventDataStoreArn': eventStoreArn,
                            'Name': eventDataStoreName
                        }
                    ]
                },
                expected_params=None
            ),
            BotoResponse(
                method='list_event_data_stores',
                service_response= {
                    'EventDataStores': [
                        {
                            'EventDataStoreArn': eventStoreArn,
                            'Name': eventDataStoreName
                        }
                    ]
                },
                expected_params=None
            ),
            BotoResponse(
                method='get_event_data_store',
                service_response= {
                    'EventDataStoreArn': eventStoreArn,
                    'Name': eventDataStoreName,
                    'Status': eventStoreStatus,
                    'CreatedTimestamp': eventStoreCreatedTimestamp,
                    'UpdatedTimestamp': eventStoreUpdatedTimestamp
                },
                expected_params={
                    'EventDataStore': eventStoreArn
                }
            ),
            BotoResponse(
                method='list_event_data_stores',
                service_response= {
                    'EventDataStores': [
                        {
                            'EventDataStoreArn': eventStoreArn,
                            'Name': eventDataStoreName
                        }
                    ]
                },
                expected_params=None
            ),
            BotoResponse(
                method='get_event_data_store',
                service_response= {
                    'EventDataStoreArn': eventStoreArn,
                    'Name': eventDataStoreName,
                    'Status': eventStoreStatus,
                    'CreatedTimestamp': eventStoreCreatedTimestamp,
                    'UpdatedTimestamp': eventStoreUpdatedTimestamp
                },
                expected_params={
                    'EventDataStore': eventStoreArn
                }
            ),           
            BotoResponse(
                method='list_event_data_stores',
                service_response= {
                    'EventDataStores': [
                        {
                            'EventDataStoreArn': eventStoreArn,
                            'Name': eventDataStoreName
                        }
                    ]
                },
                expected_params=None
            ),
            BotoResponse(
                method='get_event_data_store',
                service_response= {
                    'EventDataStoreArn': eventStoreArn,
                    'Name': eventDataStoreName,
                    'Status': eventStoreStatus,
                    'CreatedTimestamp': eventStoreCreatedTimestamp,
                    'UpdatedTimestamp': eventStoreUpdatedTimestamp
                },
                expected_params={
                    'EventDataStore': eventStoreArn
                }
            )
        ]
    )
    def test_returns_an_event_ds_resource_with_references_resolved(self):
        template = load_resources({
            'MyEventDataStore': {
                'Type': 'AWS::CloudTrail::EventDataStore',
                'Properties': {
                    'Name': self.eventDataStoreName
                }
            },
            'ResourceA': {
                'Type': 'AWS::CloudTrail::ResourcePolicy',
                'Properties': {
                    'ResourceArn': {'Fn::GetAtt': ['MyEventDataStore', 'EventDataStoreArn']},
                    'ResourcePolicy': copy.deepcopy(eventdatastore_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual(self.eventStoreId, resource.ResourceName)
        self.assertEqual('AWS::CloudTrail::EventDataStore', resource.ResourceType)

        expected_policy = copy.deepcopy(eventdatastore_policy_with_reference)
        expected_policy['Statement'][0]['Resource'] = [
            self.eventStoreArn
        ]
        expected_policy['Statement'][0]['Condition']['StringEquals'] = {
            # Status moves from CREATED -> ENABLED
            'aws:ResourceTag/EventDataStoreStatus': ['ENABLED']
        }
        expected_policy['Statement'][0]['Condition']['DateGreaterThanEquals'] = {
            'aws:TokenIssueTime': [self.eventStoreCreatedTimestamp]
        }
        expected_policy['Statement'][0]['Condition']['DateLessThanEquals'] = {
            'aws:TokenIssueTime': [self.eventStoreUpdatedTimestamp]
        }
        self.assertEqual('ResourcePolicy', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

class WhenParsingACloudTrailEventDataStorePolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::CloudTrail::ResourcePolicy',
                    'Properties': {
                        'ResourceArn': 'arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/MyEventDataStore',
                        'ResourcePolicy': copy.deepcopy(eventdatastore_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyEventDataStore", resource.ResourceName)
        self.assertEqual('AWS::CloudTrail::EventDataStore', resource.ResourceType)

        self.assertEqual('ResourcePolicy', resource.Policy.Name)
        self.assertEqual(eventdatastore_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)