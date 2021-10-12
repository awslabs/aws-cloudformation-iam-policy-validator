"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator.cfn_tools.common_schema import array_of_strings_schema

# schema for role/group/user Policies property
policies_schema = {
	'type': 'array',
	'items': {
		'type': 'object',
		'properties': {
			'PolicyDocument': {
				'type': 'object'
			},
			'PolicyName': {
				'type': 'string'
			}
		},
		'required': ['PolicyDocument', 'PolicyName']
	}
}

managed_policy_arns_schema = {
	'type': 'array',
	'items': {
		'type': 'string'
	}
}


groups_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Path': {
					'type': 'string'
				},
				'GroupName': {
					'type': 'string'
				},
				'Policies': policies_schema,
				'ManagedPolicyArns': managed_policy_arns_schema
			}
		}
	}
}

roles_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Path': {
					'type': 'string'
				},
				'RoleName': {
					'type': 'string',
					"pattern": r'^([\w+=,.@-]+)$'
				},
				'AssumeRolePolicyDocument': {
					'type': 'object'
				},
				'Policies': policies_schema,
				'ManagedPolicyArns': managed_policy_arns_schema
			},
			'required': ['AssumeRolePolicyDocument']
		}
	},
	'required': ['Properties']
}

users_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Path': {
					'type': 'string'
				},
				'UserName': {
					'type': 'string'
				},
				'Policies': policies_schema,
				'ManagedPolicyArns': managed_policy_arns_schema
			}
		}
	}
}

permission_set_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Name': {
					'type': 'string'
				},
				'InlinePolicy': {
					'type': 'object'
				},
				'ManagedPolicies': managed_policy_arns_schema
			},
			'required': ['Name']
		}
	},
	'required': ['Properties']
}

managed_policy_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'ManagedPolicyName': {
					'type': 'string'
				},
				'PolicyDocument': {
					'type': 'object'
				},
				'Path': {
					'type': 'string'
				},
				'Roles': array_of_strings_schema,
				'Users': array_of_strings_schema,
				'Groups': array_of_strings_schema
			},
			'required': ['PolicyDocument']
		}
	},
	'required': ['Properties']
}

inline_policy_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'PolicyName': {
					'type': 'string'
				},
				'PolicyDocument': {
					'type': 'object'
				},
				'Roles': array_of_strings_schema,
				'Users': array_of_strings_schema,
				'Groups': array_of_strings_schema
			},
			'required': ['PolicyName', 'PolicyDocument']
		}
	},
	'required': ['Properties']
}