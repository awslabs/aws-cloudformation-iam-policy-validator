"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import os
from unittest.mock import patch

import boto3
from botocore.stub import Stubber
from cfn_policy_validator import client


class TEST_MODE:
    AWS = 'AWS'
    OFFLINE = 'OFFLINE'


def get_test_mode():
    if os.getenv('TEST_MODE') == 'AWS':
        return TEST_MODE.AWS
    else:
        return TEST_MODE.OFFLINE


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

			# don't mock if test mode is "AWS"
			if get_test_mode() == TEST_MODE.AWS:
				func(self)
				return

			stubbers = []
			for service_name in kwargs:
				if service_name == 'assert_no_pending_responses':
					continue

				stubber = build_mock_client(service_name)
				mock_clients[service_name] = stubber.client
				stubbers.append(stubber)
				for mocks in kwargs[service_name]:
					if not isinstance(mocks, list):
						mocks = [mocks]

					for mock in mocks:
						if isinstance(mock, BotoResponse):
							stubber.add_response(mock.method, mock.service_response, mock.expected_params)
						elif isinstance(mock, BotoClientError):
							stubber.add_client_error(mock.method, mock.service_error_code,
													service_message=mock.service_message,
													expected_params=mock.expected_params)
						else:
							raise Exception(f'Invalid mock: {mock}')

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


class BotoClientError:
	def __init__(self, method, service_error_code, service_message='', expected_params=None):
		self.method = method
		self.service_error_code = service_error_code
		self.expected_params = expected_params
		self.service_message = service_message

