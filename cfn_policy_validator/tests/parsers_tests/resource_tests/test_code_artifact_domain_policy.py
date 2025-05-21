"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import copy
import unittest

from cfn_policy_validator.parsers.resource.parser import ResourceParser
from cfn_policy_validator.tests.parsers_tests import mock_node_evaluator_setup

from cfn_policy_validator.tests.utils import required_property_error, load, account_config, expected_type_error, \
    load_resources
from cfn_policy_validator.application_error import ApplicationError


code_artifact_policy_with_no_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Action': 'codeartifact:*',
            'Resource': 'arn:aws:codeartifact:us-east-1:123456789012:domain/MyTestDomain',
            'Principal': '*',
            'Condition': {
                'ArnEquals': {
                    'aws:PrincipalArn': [
                        "arn:aws:iam::123456789012:role/MyTestRoleArn"
                    ]
                }
            }
        }
    ]
}


code_artifact_policy_with_reference = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Deny',
            'Action': 'codeartifact:*',
            'Sid': {"Fn::Join": ["", ["Policy-for-", {"Fn::GetAtt": ["MyDomain", "Name"]}]]},
            'Resource': [
                {"Fn::GetAtt": ["MyDomain", "Arn"]}
            ],
            'Principal': '*',
            'Condition': {
                'ArnNotEquals': {
                    'aws:PrincipalArn': [
                        {"Fn::Join": ["", ["arn:aws:iam::", {"Fn::GetAtt": ["MyDomain", "Owner"]}, ":role/MyTestRoleArn"]]}
                    ]
                }
            }
        },
        {
            "Effect": "Allow",
            "Principal": '*',
            "Action": "kms:Decrypt",
            "Resource": [
                {"Fn::GetAtt": ["MyDomain", "EncryptionKey"]}
            ]
        }
    ]
}


class WhenParsingACodeArtifactDomainPolicyAndValidatingSchema(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CodeArtifact::Domain'
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('Properties', 'Resources.ResourceA'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_no_domain_name(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::CodeArtifact::Domain',
                    'Properties': {
                        'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_no_reference)
                    }
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(required_property_error('DomainName', 'Resources.ResourceA.Properties'), str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_domain_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': ['MyDomain'],
                    'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_no_reference)
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.DomainName', 'string', "['MyDomain']"),  str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_invalid_permissions_policy_document_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': 'MyDomain',
                    'PermissionsPolicyDocument': ['Invalid']
                }
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            ResourceParser.parse(template, account_config)

        self.assertEqual(expected_type_error('Resources.ResourceA.Properties.PermissionsPolicyDocument', 'object', "['Invalid']"),
                         str(cm.exception))

    @mock_node_evaluator_setup()
    def test_with_unsupported_function_in_unused_property(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': 'MyDomain',
                    'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_no_reference),
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
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': 'MyDomain',
                    'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_no_reference),
                    'UnusedProperty': {'Ref': 'SomeProperty'}
                }
            }
        })

        ResourceParser.parse(template, account_config)

        self.assertTrue(True, 'Should not raise error.')


class WhenParsingACodeArtifactDomainPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_a_resource(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::CodeArtifact::Domain',
                    'Properties': {
                        'DomainName': 'MyDomain',
                        'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_no_reference)
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual("MyDomain", resource.ResourceName)
        self.assertEqual('AWS::CodeArtifact::Domain', resource.ResourceType)

        self.assertEqual('PermissionsPolicyDocument', resource.Policy.Name)
        self.assertEqual(code_artifact_policy_with_no_reference, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)


class WhenParsingACodeArtifactDomainPolicyWithReferencesInEachField(unittest.TestCase):
    # this is a test to ensure that each field is being evaluated for references in a domain
    @mock_node_evaluator_setup()
    def test_returns_a_resource_with_references_resolved(self):
        template = load_resources({
            'MyDomain': {
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': 'MyCustomDomainName',
                    'EncryptionKey': 'arn:aws:kms:us-west-2:123456789012:key/12345678-9abc-def1-2345-6789abcdef12'
                }
            },
            'ResourceA': {
                'Type': 'AWS::CodeArtifact::Domain',
                'Properties': {
                    'DomainName': {'Ref': 'MyDomain'},
                    'PermissionsPolicyDocument': copy.deepcopy(code_artifact_policy_with_reference)
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 1)

        resource = resources[0]
        self.assertEqual(f'arn:aws:codeartifact:{account_config.region}:{account_config.account_id}:domain/MyDomain', resource.ResourceName)
        self.assertEqual('AWS::CodeArtifact::Domain', resource.ResourceType)

        expected_policy = copy.deepcopy(code_artifact_policy_with_reference)
        expected_policy['Statement'][0]['Sid'] = f'Policy-for-MyCustomDomainName'
        expected_policy['Statement'][0]['Resource'] = [
            f'arn:aws:codeartifact:{account_config.region}:{account_config.account_id}:domain/MyDomain'
        ]
        expected_policy['Statement'][0]['Condition']['ArnNotEquals']['aws:PrincipalArn'][0] = f'arn:aws:iam::{account_config.account_id}:role/MyTestRoleArn'
        expected_policy['Statement'][1]['Resource'] = [
            f'arn:aws:kms:us-west-2:123456789012:key/12345678-9abc-def1-2345-6789abcdef12'
        ]
        self.assertEqual('PermissionsPolicyDocument', resource.Policy.Name)
        self.assertEqual(expected_policy, resource.Policy.Policy)
        self.assertEqual('/', resource.Policy.Path)

class WhenParsingACodeArtifactDomainWithNoPermissionsPolicy(unittest.TestCase):
    @mock_node_evaluator_setup()
    def test_returns_no_resources(self):
        template = load({
            'Resources': {
                'TestDomain': {
                    'Type': 'AWS::CodeArtifact::Domain',
                    'Properties': {
                        'DomainName': 'MyDomain'
                    }
                }
            }
        })

        resources = ResourceParser.parse(template, account_config)
        self.assertEqual(len(resources), 0)
