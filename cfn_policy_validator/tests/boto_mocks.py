"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import uuid
from datetime import datetime
from unittest.mock import patch

import boto3
from botocore.stub import Stubber
from cfn_policy_validator import client


def build_mock_client(service_name):
	mock_client = boto3.client(service_name)
	stubber = Stubber(mock_client)
	stubber.activate()
	return stubber


def get_mock_client(service_name, region_name, client_config=None):
	if service_name not in mock_clients:
		raise Exception(f'Attempt to get boto3 client for service {service_name} failed.  No mocks found for {service_name}.')

	return mock_clients[service_name]


mock_clients = {}


def mock_test_setup(**kwargs):
	def decorator(func):
		def wrapper(*args):
			self = args[0]

			stubbers = []
			for service_name in kwargs:
				if service_name == 'assert_no_pending_responses':
					continue

				stubber = build_mock_client(service_name)
				mock_clients[service_name] = stubber.client
				stubbers.append(stubber)
				for responses in kwargs[service_name]:
					if not isinstance(responses, list):
						responses = [responses]

					for response in responses:
						stubber.add_response(response.method, response.service_response, response.expected_params)

			with patch.object(client, 'build') as mock_client_builder:
				mock_client_builder.side_effect = get_mock_client
				func(self)

			should_assert_no_pending_responses = kwargs.get('assert_no_pending_responses')
			if should_assert_no_pending_responses:
				for stubber in stubbers:
					stubber.assert_no_pending_responses()

			mock_clients.clear()

		return wrapper
	return decorator


class BotoResponse:
	def __init__(self, method, service_response, expected_params=None):
		self.method = method
		self.service_response = service_response
		self.expected_params = expected_params
