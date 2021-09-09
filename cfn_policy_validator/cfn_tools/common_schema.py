"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
string_schema = {
	'type': 'string'
}

array_of_strings_schema = {
	'type': 'array',
	'items': {
		'type': 'string'
	}
}