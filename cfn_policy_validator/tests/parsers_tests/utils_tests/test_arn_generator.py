"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.arn_generator import ArnGenerator
from cfn_policy_validator.tests.utils import account_config, load, load_resources, required_property_error, \
    expected_type_error


def build_resource(resource):
    template = load({
        'Resources': {
            'ResourceA': resource
        }
    })
    return template['Resources']['ResourceA']


class WhenGeneratingAnArnForAKnownResource(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_generates_global_arn_from_ref(self):
        resource = build_resource({'Type': 'AWS::IAM::ManagedPolicy'})
        arn = self.arn_generator.try_generate_arn("MyTestPolicy", resource, "Ref")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:policy/MyTestPolicy", arn)

    def test_generates_arn_from_attribute(self):
        resource = build_resource({'Type': "AWS::ECS::Cluster"})
        arn = self.arn_generator.try_generate_arn("MyTestCluster", resource, "Arn")
        self.assertEqual(f"arn:aws:ecs:{account_config.region}:{account_config.account_id}:cluster/MyTestCluster", arn)


class WhenGeneratingAnArnForAnUnknownResource(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_does_not_generate_arn(self):
        resource = build_resource({'Type': "AWS::EC2::Instance"})
        arn = self.arn_generator.try_generate_arn("AnyName", resource, "Ref")
        self.assertIsNone(arn)


class WhenGeneratingAnArnAndValidatingSchema(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_with_invalid_resource_type(self):
        resource = build_resource({'Type': 'AWS::Instance'})

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('AnyName', resource, 'Ref')

        self.assertEqual('Invalid resource type: AWS::Instance', str(cm.exception))


class WhenGeneratingAnArnForACloudFormationModule(unittest.TestCase):
    def test_should_raise_error(self):
        arn_generator = ArnGenerator(account_config)
        resource = build_resource({'Type': 'Org::ServiceName::UseCase::MODULE'})

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('AnyName', resource, 'Ref')

        self.assertEqual('Unable to resolve Org::ServiceName::UseCase::MODULE. CloudFormation modules are not yet supported.', str(cm.exception))


class WhenGeneratingAnArnForAnIAMRoleAndValidatingSchema(unittest.TestCase):
    def test_with_no_properties(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::Role'
            }
        })

        arn_generator = ArnGenerator(account_config)

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('MyRole', template['Resources']['ResourceA'], 'Arn')

        self.assertEqual(required_property_error('Properties', 'ResourceA'), str(cm.exception))

    def test_with_invalid_path_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'Path': []
                }
            }
        })

        arn_generator = ArnGenerator(account_config)

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('MyRole', template['Resources']['ResourceA'], 'Arn')

        self.assertEqual(expected_type_error('ResourceA.Properties.Path', 'string', '[]'), str(cm.exception))

    def test_with_invalid_role_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'RoleName': []
                }
            }
        })

        arn_generator = ArnGenerator(account_config)

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('MyRole', template['Resources']['ResourceA'], 'Arn')

        self.assertEqual(expected_type_error('ResourceA.Properties.RoleName', 'string', '[]'), str(cm.exception))


class WhenGeneratingAnArnForAnIAMRole(unittest.TestCase):
    @staticmethod
    def add_resource_to_template(resource):
        template = load({
            'Parameters': {
                'MyRoleParameter': {'Type': 'string'},
                'MyPathParameter': {'Type': 'string'}
            },
            'Resources': {
                'InvalidRoleReference': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'RoleName': {'NotA': 'String'},
                        'Path': ['NotA', 'String']
                    }
                },
                'ResourceA': resource
            }
        },
        {
            'MyRoleParameter': 'MyCustomRoleName',
            'MyPathParameter': '/my/custom/path/'
        })

        return template['Resources']['ResourceA']

    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_generates_arn_with_path_and_name(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::Role',
            'Properties': {
                'Path': {'Ref': 'MyPathParameter'},
                'RoleName': {'Ref': 'MyRoleParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyRole", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:role/my/custom/path/MyCustomRoleName", arn)

    def test_generates_arn_with_path_and_resource_name_if_no_name(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::Role',
            'Properties': {
                'Path': {'Ref': 'MyPathParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyRole", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:role/my/custom/path/MyRole", arn)

    def test_generates_arn_with_default_path_and_name_if_no_path(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::Role',
            'Properties': {
                'RoleName': {'Ref': 'MyRoleParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyRole", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:role/MyCustomRoleName", arn)


class WhenGeneratingAnArnForAnIAMUserAndValidatingSchema(unittest.TestCase):
    def test_with_invalid_path_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::User',
                'Properties': {
                    'Path': []
                }
            }
        })

        arn_generator = ArnGenerator(account_config)

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('MyUser', template['Resources']['ResourceA'], 'Arn')

        self.assertEqual(expected_type_error('ResourceA.Properties.Path', 'string', '[]'), str(cm.exception))

    def test_with_invalid_user_name_type(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::IAM::User',
                'Properties': {
                    'UserName': []
                }
            }
        })

        arn_generator = ArnGenerator(account_config)

        with self.assertRaises(ApplicationError) as cm:
            arn_generator.try_generate_arn('MyUser', template['Resources']['ResourceA'], 'Arn')

        self.assertEqual(expected_type_error('ResourceA.Properties.UserName', 'string', '[]'), str(cm.exception))


class WhenGeneratingAnArnForAnIAMUser(unittest.TestCase):
    @staticmethod
    def add_resource_to_template(resource):
        template = load({
            'Parameters': {
                'MyUserParameter': {'Type': 'string'},
                'MyPathParameter': {'Type': 'string'}
            },
            'Resources': {
                'ResourceA': resource
            }
        },
        {
            'MyUserParameter': 'MyCustomUserName',
            'MyPathParameter': '/my/custom/user/path/'
        })

        return template['Resources']['ResourceA']

    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_generates_arn_with_path_and_name(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::User',
            'Properties': {
                'Path': {'Ref': 'MyPathParameter'},
                'UserName': {'Ref': 'MyUserParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyUser", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:user/my/custom/user/path/MyCustomUserName", arn)

    def test_generates_arn_with_path_and_resource_name_if_no_name(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::User',
            'Properties': {
                'Path': {'Ref': 'MyPathParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyUser", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:user/my/custom/user/path/MyUser", arn)

    def test_generates_arn_with_default_path_and_name_if_no_path(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::User',
            'Properties': {
                'UserName': {'Ref': 'MyUserParameter'}
            }
        })
        arn = self.arn_generator.try_generate_arn("MyUser", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:user/MyCustomUserName", arn)

    def test_generates_arn_with_all_defaults_if_no_properties(self):
        resource = self.add_resource_to_template({
            'Type': 'AWS::IAM::User'
        })
        arn = self.arn_generator.try_generate_arn("MyUser", resource, "Arn")
        self.assertEqual(f"arn:aws:iam::{account_config.account_id}:user/MyUser", arn)


class WhenGeneratingAnArnForELBv2ResourcesAndValidatingSchema(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_with_invalid_load_balancer_type_type(self):
        resource = build_resource({
            'Type': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
            'Properties': {
                'Type': []
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('MyLB', resource, 'Ref')

        self.assertEqual(expected_type_error('ResourceA.Properties.Type', 'string', '[]'), str(cm.exception))

    def test_with_invalid_load_balancer_listener_protocol_type(self):
        resource = build_resource({
            'Type': 'AWS::ElasticLoadBalancingV2::Listener',
            'Properties': {
                'Protocol': []
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('MyLB', resource, 'Ref')

        self.assertEqual(expected_type_error('ResourceA.Properties.Protocol', 'string', '[]'), str(cm.exception))

    def test_with_invalid_load_balancer_target_group_protocol_type(self):
        resource = build_resource({
            'Type': 'AWS::ElasticLoadBalancingV2::TargetGroup',
            'Properties': {
                'Protocol': []
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('MyLB', resource, 'Ref')

        self.assertEqual(expected_type_error('ResourceA.Properties.Protocol', 'string', '[]'), str(cm.exception))


# ELBv2 resources have a specific generation pattern that depends on if the ELB is an ALB or an NLB
class WhenGeneratingAnArnForELBv2Resources(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_does_not_generate_arn_for_alb_attributes(self):
        resource = build_resource({'Type': "AWS::ElasticLoadBalancingV2::LoadBalancer"})
        arn = self.arn_generator.try_generate_arn("MyAlb", resource, "Arn")
        self.assertIsNone(arn)

    def test_generates_arn_for_implicit_alb(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::LoadBalancer"
        })
        arn = self.arn_generator.try_generate_arn("MyAlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/app/MyAlb/MyAlb", arn)

    def test_generates_arn_for_explicit_alb(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::LoadBalancer",
            'Properties': {
                'Type': 'application'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyAlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/app/MyAlb/MyAlb", arn)

    def test_generates_arn_for_nlb(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::LoadBalancer",
            'Properties': {
                'Type': 'network'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyNlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/net/MyNlb/MyNlb", arn)

    def test_generates_arn_for_gwy_lb(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::LoadBalancer",
            'Properties': {
                'Type': 'gateway'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyGwlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/gwy/MyGwlb/MyGwlb", arn)

    def test_generates_arn_for_alb_listener(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::Listener",
            'Properties': {
                'Protocol': 'HTTPS'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyAlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:listener/app/MyAlb/MyAlb/MyAlb", arn)

    def test_generates_arn_for_nlb_listener(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::Listener",
            'Properties': {
                'Protocol': 'TCP'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyNlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:listener/net/MyNlb/MyNlb/MyNlb", arn)

    def test_generates_arn_for_gwy_listener(self):
        resource = build_resource({
            'Type': 'AWS::ElasticLoadBalancingV2::Listener',
            'Properties': {}
        })
        arn = self.arn_generator.try_generate_arn("MyGwlb", resource, "Ref")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:listener/gwy/MyGwlb/MyGwlb/MyGwlb", arn)

    def test_generates_arn_for_alb_target_group_with_no_protocol(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::TargetGroup",
            'Properties': {}
        })
        arn = self.arn_generator.try_generate_arn("MyAlbTargetGroup", resource, "LoadBalancerArns")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/app/MyAlbTargetGroup/MyAlbTargetGroup", arn)

    def test_generates_arn_for_alb_target_group(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::TargetGroup",
            'Properties': {
                'Protocol': 'HTTPS'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyAlbTargetGroup", resource, "LoadBalancerArns")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/app/MyAlbTargetGroup/MyAlbTargetGroup", arn)

    def test_generates_arn_for_nlb_target_group(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::TargetGroup",
            'Properties': {
                'Protocol': 'TCP'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyNlbTargetGroup", resource, "LoadBalancerArns")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/net/MyNlbTargetGroup/MyNlbTargetGroup", arn)

    def test_generates_arn_for_gwy_target_group(self):
        resource = build_resource({
            'Type': "AWS::ElasticLoadBalancingV2::TargetGroup",
            'Properties': {
                'Protocol': 'GENEVE'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyGwyTargetGroup", resource, "LoadBalancerArns")
        self.assertEqual(f"arn:aws:elasticloadbalancing:{account_config.region}:{account_config.account_id}:loadbalancer/gwy/MyGwyTargetGroup/MyGwyTargetGroup", arn)


class WhenGeneratingAnArnForNetworkFirewallRuleGroupsAndValidatingSchema(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_with_no_rulegroup_type(self):
        resource = build_resource({
            'Type': 'AWS::NetworkFirewall::RuleGroup',
            'Properties': {}
        })

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('MyLB', resource, 'Ref')

        self.assertEqual(required_property_error('Type', 'ResourceA.Properties'), str(cm.exception))

    def test_with_invalid_rulegroup_type(self):
        resource = build_resource({
            'Type': 'AWS::NetworkFirewall::RuleGroup',
            'Properties': {
                'Type': []
            }
        })

        with self.assertRaises(ApplicationError) as cm:
            self.arn_generator.try_generate_arn('MyLB', resource, 'Ref')

        self.assertEqual(expected_type_error('ResourceA.Properties.Type', 'string', '[]'), str(cm.exception))


# Network Firewall Rulegroup resources have a specific pattern that depends on if the NFW rule is stateful or stateless
class WhenGeneratingAnArnForNetworkFirewallRuleGroups(unittest.TestCase):
    def setUp(self):
        self.arn_generator = ArnGenerator(account_config)

    def test_does_not_generate_arn_for_alb_attributes(self):
        resource = build_resource({'Type': "AWS::NetworkFirewall::RuleGroup"})
        arn = self.arn_generator.try_generate_arn("MyNFW", resource, "Arn")
        self.assertIsNone(arn)

    def test_generates_arn_for_stateful_rulegroup(self):
        resource = build_resource({
            'Type': "AWS::NetworkFirewall::RuleGroup",
            'Properties': {
                'Type': 'STATEFUL'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyNfw", resource, "Ref")
        self.assertEqual(f"arn:aws:network-firewall:{account_config.region}:{account_config.account_id}:stateful-rulegroup/MyNfw", arn)

    def test_generates_arn_for_stateless_rulegroup(self):
        resource = build_resource({
            'Type': "AWS::NetworkFirewall::RuleGroup",
            'Properties': {
                'Type': 'STATELESS'
            }
        })
        arn = self.arn_generator.try_generate_arn("MyNfw", resource, "Ref")
        self.assertEqual(f"arn:aws:network-firewall:{account_config.region}:{account_config.account_id}:stateless-rulegroup/MyNfw", arn)
