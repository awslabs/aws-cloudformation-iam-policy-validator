"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
iam_role_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Path': {
					'type': 'string'
				},
				'RoleName': {
					'type': 'string'
				}
			}
		}
	},
	'required': ['Properties']
}

iam_user_schema = {
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
				}
			}
		}
	}
}

elbv2_load_balancer_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Type': {
					'type': 'string'
				}
			}
		}
	}
}

elbv2_listener_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Protocol': {
					'type': 'string'
				}
			}
		}
	},
	'required': ['Properties']
}

elbv2_target_group_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Protocol': {
					'type': 'string'
				}
			}
		}
	}
}

network_firewall_rulegroup_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'Type': {
					'type': 'string'
				}
			},
			'required': ['Type']
		}
	}
}