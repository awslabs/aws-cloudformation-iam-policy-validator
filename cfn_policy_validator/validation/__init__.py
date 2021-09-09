"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import datetime


def default_to_json(value):
	if isinstance(value, datetime.date):
		return value.isoformat()
	else:
		return value.__dict__
