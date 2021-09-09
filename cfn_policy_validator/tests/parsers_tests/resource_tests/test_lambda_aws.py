"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.parsers.output import Resource, Policy

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
	load_resources
from cfn_policy_validator.application_error import ApplicationError


class WhenParsingALambdaPermissionsPolicyAndValidatingSchema(unittest.TestCase):
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	def test_with_no_action(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission',
				'Properties': {
					'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
					'Principal': 's3.amazonaws.com'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Action', 'ResourceA.Properties'), str(cm.exception))

	def test_with_no_function_name(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission',
				'Properties': {
					'Action': 'lambda:InvokeFunction',
					'Principal': 's3.amazonaws.com'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('FunctionName', 'ResourceA.Properties'), str(cm.exception))

	def test_with_no_principal(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission',
				'Properties': {
					'Action': 'lambda:InvokeFunction',
					'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Principal', 'ResourceA.Properties'), str(cm.exception))

	def test_with_unsupported_function_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission',
				'Properties': {
					'Action': 'lambda:InvokeFunction',
					'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
					'Principal': 's3.amazonaws.com',
					'UnusedProperty': {"Fn::GetAZs": {"Ref": "AWS::Region"}}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	def test_with_ref_to_parameter_in_unused_property(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::Permission',
				'Properties': {
					'Action': 'lambda:InvokeFunction',
					'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
					'Principal': 's3.amazonaws.com',
					'UnusedProperty': {'Ref': 'SomeProperty'}
				}
			}
		})

		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


def _build_lambda_permissions_policy(action='lambda:InvokeFunction', function_name='MyFunction', principal='MyPrincipal',
									 source_account=None, source_arn=None):
	template = load_resources({
		'ResourceA': {
			'Type': 'AWS::Lambda::Permission',
			'Properties': {
				'Action': action,
				'FunctionName': function_name,
				'Principal': principal
			}
		}
	})

	if source_account is not None:
		template['Resources']['ResourceA']['Properties']['SourceAccount'] = source_account

	if source_arn is not None:
		template['Resources']['ResourceA']['Properties']['SourceArn'] = source_arn

	return template


class WhenParsingALambdaPermissionsPolicyWithInvalidPropertyType(unittest.TestCase):
	def assert_invalid_type(self, template, path, expected_type, invalid_value):
		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error(path, expected_type, invalid_value), str(cm.exception))

	def test_invalid_action_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_permissions_policy(action=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.Action", 'string', invalid_value)

	def test_invalid_function_name_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_permissions_policy(function_name=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.FunctionName", 'string', invalid_value)

	def test_invalid_principal_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_permissions_policy(principal=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.Principal", 'string', invalid_value)

	def test_invalid_source_arn_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_permissions_policy(source_arn=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.SourceArn", 'string', invalid_value)

	def test_invalid_source_account_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_permissions_policy(source_account=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.SourceAccount", 'string', invalid_value)


class WhenParsingALambdaPermissionsPolicy(unittest.TestCase):
	@staticmethod
	def __build_expected_policy():
		return {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 'lambda:InvokeFunction',
				'Principal': {
					'AWS': 'MyPrincipal'
				},
				'Resource': f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:MyFunction'
			}]
		}

	@staticmethod
	def __modify_statement(policy, property_name, property_value):
		policy['Statement'][0][property_name] = property_value

	def test_function_name_is_full_arn(self):
		function_name = f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:MyFunction'

		template = _build_lambda_permissions_policy(function_name=function_name)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_function_name_is_partial_arn_with_region(self):
		partial_function_arn = f'{account_config.region}:{account_config.account_id}:function:MyFunction'

		template = _build_lambda_permissions_policy(function_name=partial_function_arn)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_function_name_is_partial_arn_with_account(self):
		partial_function_arn = f'{account_config.account_id}:function:MyFunction'

		template = _build_lambda_permissions_policy(function_name=partial_function_arn)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_function_name_is_partial_arn_with_function(self):
		partial_function_arn = 'function:MyFunction'

		template = _build_lambda_permissions_policy(function_name=partial_function_arn)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_function_name_is_name(self):
		function_name = 'MyFunction'
		self.__test_function_name(function_name)

	def test_function_name_is_name_and_alias(self):
		function_name = 'MyFunction:v1'
		self.__test_function_name(function_name)

	def __test_function_name(self, function_name):
		template = _build_lambda_permissions_policy(function_name=function_name)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Resource', f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:{function_name}')
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_principal_name_is_a_service(self):
		template = _build_lambda_permissions_policy(principal="s3.amazonaws.com")
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Principal', {'Service': 's3.amazonaws.com'})
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_principal_name_is_an_account(self):
		template = _build_lambda_permissions_policy(principal="123456")
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Principal', {'AWS': '123456'})
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_source_account_is_included(self):
		source_account = '5678910'
		template = _build_lambda_permissions_policy(source_account=source_account)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Condition', {'StringEquals': {'AWS:SourceAccount': source_account}})
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_source_arn_is_included(self):
		source_arn = 'aws:aws:s3:::my-bucket'
		template = _build_lambda_permissions_policy(source_arn=source_arn)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Condition', {'ArnLike': {'AWS:SourceArn': source_arn}})
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_source_account_and_source_arn_are_included(self):
		source_arn = 'aws:aws:s3:::my-bucket'
		source_account = '5678910'
		template = _build_lambda_permissions_policy(source_account=source_account, source_arn=source_arn)
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("MyFunction", resource.ResourceName)
		self.assertEqual('AWS::Lambda::Function', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Condition',
								{
									'ArnLike': {'AWS:SourceArn': source_arn},
									'StringEquals': {'AWS:SourceAccount': source_account}
								})
		self.assertEqual('PermissionsPolicy', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)


class WhenParsingMultipleLambdaPermissionsPolicies(unittest.TestCase):
	def test_resources_are_returned(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Lambda::Permission',
					'Properties': {
						'Action': 'lambda:InvokeFunction',
						'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
						'Principal': 's3.amazonaws.com'
					}
				},
				'ResourceB': {
					'Type': 'AWS::Lambda::Permission',
					'Properties': {
						'Action': 'lambda:InvokeFunction',
						'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
						'Principal': '1234567'
					}
				},
				'ResourceC': {
					'Type': 'AWS::Lambda::Permission',
					'Properties': {
						'Action': 'lambda:InvokeFunction',
						'FunctionName': 'arn:aws:lambda:us-east-1:123456:function:MyFunction2',
						'Principal': '1234567'
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy_doc_a = {
			'Version': '2012-10-17',
			'Statement': [{
					'Effect': 'Allow',
					'Action': 'lambda:InvokeFunction',
					'Resource': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
					'Principal': {
						'Service': 's3.amazonaws.com'
					}
				},
				{
					'Effect': 'Allow',
					'Action': 'lambda:InvokeFunction',
					'Resource': 'arn:aws:lambda:us-east-1:123456:function:MyFunction1',
					'Principal': {
						'AWS': '1234567'
					}
				}]
		}

		expected_policy_a = Policy("PermissionsPolicy", expected_policy_doc_a)
		expected_resource_a = Resource('MyFunction1', 'AWS::Lambda::Function', expected_policy_a)

		self.assertIn(expected_resource_a, resources)

		expected_policy_doc_b = {
			'Version': '2012-10-17',
			'Statement': [
				{
					'Effect': 'Allow',
					'Action': 'lambda:InvokeFunction',
					'Resource': 'arn:aws:lambda:us-east-1:123456:function:MyFunction2',
					'Principal': {
						'AWS': '1234567'
					}
				}]
		}

		expected_policy_b = Policy('PermissionsPolicy', expected_policy_doc_b)
		expected_resource_b = Resource('MyFunction2', 'AWS::Lambda::Function', expected_policy_b)

		self.assertIn(expected_resource_b, resources)


class WhenParsingLambdaPermissionsPolicyWithReferencesInEachField(unittest.TestCase):
	def test_references_are_resolved(self):
		template = load({
			'Parameters': {
				'ActionParameter': {'Type': 'string'},
				'PrincipalParameter': {'Type': 'string'}
			},
			'Resources': {
				'MyS3Bucket': {
					'Type': 'AWS::S3::Bucket'
				},
				'MyFunction': {
					'Type': 'AWS::Lambda::Function'
				},
				'ResourceA': {
					'Type': 'AWS::Lambda::Permission',
					'Properties': {
						'Action': {'Ref': 'ActionParameter'},
						'FunctionName': {'Fn::GetAtt': ['MyFunction', 'Arn']},
						'Principal': {'Ref': 'PrincipalParameter'},
						'SourceAccount': {'Ref': 'AWS::AccountId'},
						'SourceArn': {'Fn::GetAtt': ['MyS3Bucket', 'Arn']}
					}
				}
			}
		}, {
			'ActionParameter': 'lambda:GetFunction',
			'PrincipalParameter': '1234567'
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy_doc = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 'lambda:GetFunction',
				'Resource': f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:function:MyFunction',
				'Principal': {
					'AWS': '1234567'
				},
				'Condition': {
					'StringEquals': {
						'AWS:SourceAccount': account_config.account_id
					},
					'ArnLike': {
						'AWS:SourceArn': 'arn:aws:s3:::MyS3Bucket'
					}
				}
			}]
		}

		expected_policy = Policy("PermissionsPolicy", expected_policy_doc)
		expected_resource = Resource('MyFunction', 'AWS::Lambda::Function', expected_policy)

		self.assertIn(expected_resource, resources)


class WhenParsingALambdaLayerVersionPermissionsPolicyAndValidatingSchema(unittest.TestCase):
	def test_with_no_properties(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::LayerVersionPermission'
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

	def test_with_no_action(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::LayerVersionPermission',
				'Properties': {
					'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
					'Principal': '1234567'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Action', 'ResourceA.Properties'), str(cm.exception))

	def test_with_no_layer_version_arn(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::LayerVersionPermission',
				'Properties': {
					'Action': 'lambda:GetLayerVersion',
					'Principal': '1234567'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('LayerVersionArn', 'ResourceA.Properties'), str(cm.exception))

	def test_with_no_principal(self):
		template = load_resources({
			'ResourceA': {
				'Type': 'AWS::Lambda::LayerVersionPermission',
				'Properties': {
					'Action': 'lambda:GetLayerVersion',
					'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1'
				}
			}
		})

		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(required_property_error('Principal', 'ResourceA.Properties'), str(cm.exception))


def _build_lambda_layer_version_permissions_policy(action='lambda:GetLayerVersion',
												   layer_version_arn='arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
												   principal='123456',
												   organization_id=None):
	template = load_resources({
		'ResourceA': {
			'Type': 'AWS::Lambda::LayerVersionPermission',
			'Properties': {
				'Action': action,
				'LayerVersionArn': layer_version_arn,
				'Principal': principal
			}
		}
	})

	if organization_id is not None:
		template['Resources']['ResourceA']['Properties']['OrganizationId'] = organization_id

	return template


class WhenParsingALambdaLayerVersionPermissionsPolicyWithInvalidPropertyType(unittest.TestCase):
	def assert_invalid_type(self, template, path, expected_type, invalid_value):
		with self.assertRaises(ApplicationError) as cm:
			ResourceParser.parse(template, account_config)

		self.assertEqual(expected_type_error(path, expected_type, invalid_value), str(cm.exception))

	def test_invalid_action_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_layer_version_permissions_policy(action=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.Action", "string", invalid_value)

	def test_invalid_layer_version_arn_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_layer_version_permissions_policy(layer_version_arn=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.LayerVersionArn", "string", invalid_value)

	def test_invalid_principal_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_layer_version_permissions_policy(principal=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.Principal", "string", invalid_value)

	def test_invalid_organization_id_type(self):
		invalid_value = ['Invalid']
		template = _build_lambda_layer_version_permissions_policy(organization_id=invalid_value)
		self.assert_invalid_type(template, "ResourceA.Properties.OrganizationId", "string", invalid_value)

	def test_with_unsupported_function_in_unused_property(self):
		template = _build_lambda_layer_version_permissions_policy()
		template['Resources']['ResourceA']['Properties']['UnusedProperty'] = {"Fn::GetAZs": {"Ref": "AWS::Region"}}
		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')

	def test_with_ref_to_parameter_in_unused_property(self):
		template = _build_lambda_layer_version_permissions_policy()
		template['Resources']['ResourceA']['Properties']['UnusedProperty'] = {'Ref': 'SomeProperty'}
		ResourceParser.parse(template, account_config)

		self.assertTrue(True, 'Should not raise error.')


class WhenParsingALambdaLayerVersionPermissionsPolicy(unittest.TestCase):
	@staticmethod
	def __build_template(principal='123456789123'):
		return load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Lambda::LayerVersionPermission',
					'Properties': {
						'Action': 'lambda:GetLayerVersion',
						'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
						'Principal': principal
					}
				}
			}
		})

	@staticmethod
	def __build_expected_policy():
		return {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 'lambda:GetLayerVersion',
				'Principal': {
					'AWS': '123456789123'
				},
				'Resource': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1'
			}]
		}

	@staticmethod
	def __modify_statement(policy, property_name, property_value):
		policy['Statement'][0][property_name] = property_value

	def test_principal_is_layer_arn(self):
		template = self.__build_template()
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("LayerABC:1", resource.ResourceName)
		self.assertEqual('AWS::Lambda::LayerVersion', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.assertEqual('LayerVersionPermission', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_principal_is_star(self):
		template = self.__build_template(principal='*')
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("LayerABC:1", resource.ResourceName)
		self.assertEqual('AWS::Lambda::LayerVersion', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Principal', {'AWS': '*'})
		self.assertEqual('LayerVersionPermission', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_principal_is_account_id(self):
		template = self.__build_template(principal='123456789123')
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("LayerABC:1", resource.ResourceName)
		self.assertEqual('AWS::Lambda::LayerVersion', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Principal', {'AWS': '123456789123'})
		self.assertEqual('LayerVersionPermission', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)

	def test_has_organization_id(self):
		template = self.__build_template()
		template['Resources']['ResourceA']['Properties']['OrganizationId'] = 'o-12345'
		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		resource = resources[0]
		self.assertEqual("LayerABC:1", resource.ResourceName)
		self.assertEqual('AWS::Lambda::LayerVersion', resource.ResourceType)

		expected_policy_doc = self.__build_expected_policy()
		self.__modify_statement(expected_policy_doc, 'Condition', {'StringEquals': {'aws:PrincipalOrgID': 'o-12345'}})

		self.assertEqual('LayerVersionPermission', resource.Policy.Name)
		self.assertEqual(expected_policy_doc, resource.Policy.Policy)
		self.assertEqual('/', resource.Policy.Path)


class WhenParsingMultipleLambdaLayerVersionPermissionsPolicies(unittest.TestCase):
	def test_resources_are_returned(self):
		template = load({
			'Resources': {
				'ResourceA': {
					'Type': 'AWS::Lambda::LayerVersionPermission',
					'Properties': {
						'Action': 'lambda:GetLayerVersion',
						'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
						'Principal': '123456789123'
					}
				},
				'ResourceB': {
					'Type': 'AWS::Lambda::LayerVersionPermission',
					'Properties': {
						'Action': 'lambda:GetLayerVersion',
						'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
						'Principal': '123456789123'
					}
				},
				'ResourceC': {
					'Type': 'AWS::Lambda::LayerVersionPermission',
					'Properties': {
						'Action': 'lambda:GetLayerVersion',
						'LayerVersionArn': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:2',
						'Principal': '123456789123'
					}
				}
			}
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 2)

		expected_policy_doc_a = {
			'Version': '2012-10-17',
			'Statement': [{
					'Effect': 'Allow',
					'Action': 'lambda:GetLayerVersion',
					'Resource': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
					'Principal': {
						'AWS': '123456789123'
					}
				},
				{
					'Effect': 'Allow',
					'Action': 'lambda:GetLayerVersion',
					'Resource': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:1',
					'Principal': {
						'AWS': '123456789123'
					}
				}]
		}

		expected_policy_a = Policy("LayerVersionPermission", expected_policy_doc_a)
		expected_resource_a = Resource('LayerABC:1', 'AWS::Lambda::LayerVersion', expected_policy_a)

		self.assertIn(expected_resource_a, resources)

		expected_policy_doc_b = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 'lambda:GetLayerVersion',
				'Resource': 'arn:aws:lambda:us-east-1:123456789123:layer:LayerABC:2',
				'Principal': {
					'AWS': '123456789123'
				}
			}]
		}

		expected_policy_b = Policy('LayerVersionPermission', expected_policy_doc_b)
		expected_resource_b = Resource('LayerABC:2', 'AWS::Lambda::LayerVersion', expected_policy_b)

		self.assertIn(expected_resource_b, resources)


class WhenParsingLambdaLayerVersionPermissionsPolicyWithReferencesInEachField(unittest.TestCase):
	def test_references_are_resolved(self):
		template = load({
			'Parameters': {
				'ActionParameter': {'Type': 'string'},
				'PrincipalParameter': {'Type': 'string'},
				'OrganizationIdParameter': {'Type': 'string'}
			},
			'Resources': {
				'MyLayerVersion': {
					'Type': 'AWS::Lambda::LayerVersion'
				},
				'ResourceA': {
					'Type': 'AWS::Lambda::LayerVersionPermission',
					'Properties': {
						'Action': {'Ref': 'ActionParameter'},
						'LayerVersionArn': {'Ref': 'MyLayerVersion'},
						'Principal': {'Ref': 'PrincipalParameter'},
						'OrganizationId': {'Ref': 'OrganizationIdParameter'}
					}
				}
			}
		}, {
			'ActionParameter': 'lambda:GetLayerVersion',
			'PrincipalParameter': '123456789123',
			'OrganizationIdParameter': 'o-12345'
		})

		resources = ResourceParser.parse(template, account_config)
		self.assertEqual(len(resources), 1)

		expected_policy_doc = {
			'Version': '2012-10-17',
			'Statement': [{
				'Effect': 'Allow',
				'Action': 'lambda:GetLayerVersion',
				'Resource': f'arn:aws:lambda:{account_config.region}:{account_config.account_id}:layer:MyLayerVersion:MyLayerVersion',
				'Principal': {
					'AWS': '123456789123'
				},
				'Condition': {
					'StringEquals': {
						'aws:PrincipalOrgID': 'o-12345'
					}
				}
			}]
		}

		expected_policy = Policy("LayerVersionPermission", expected_policy_doc)
		expected_resource = Resource('MyLayerVersion:MyLayerVersion', 'AWS::Lambda::LayerVersion', expected_policy)

		self.assertIn(expected_resource, resources)
