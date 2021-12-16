"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging

from abc import ABC

from botocore.exceptions import ClientError

from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.identity_schemas import groups_schema, managed_policy_schema, \
	roles_schema, inline_policy_schema, users_schema, permission_set_schema
from cfn_policy_validator.parsers.utils.arn_generator import ArnGenerator
from cfn_policy_validator.parsers.output import Role, User, Policy, Group, PermissionSet
from cfn_policy_validator.parsers.utils.topological_sorter import TopologicalSorter


LOGGER = logging.getLogger("cfn-policy-validator")


class IdentityParser:
	"""
	Parses identity policies from IAM CloudFormation resources.  Note that identity policies may have dependencies
	on each other (e.g. policies attached to principals).
	"""

	@classmethod
	def parse(cls, template, account_config):
		parsers = {
			'AWS::IAM::Role': RoleParser(account_config.region),
			'AWS::IAM::Policy': InlinePolicyParser(),
			'AWS::IAM::ManagedPolicy': ManagedPolicyParser(account_config),
			'AWS::IAM::User': UserParser(account_config.region),
			'AWS::IAM::Group': GroupParser(account_config.region),
			'AWS::SSO::PermissionSet': PermissionSetParser(account_config.region)
		}

		# topologically sort which allows us to process dependent resources first
		sorter = TopologicalSorter(template)
		sorted_resources = sorter.sort_resources()

		for resource in sorted_resources:
			resource_type = resource.value['Type']
			parser = parsers.get(resource_type)
			if parser is not None:
				LOGGER.info(f'Parsing resource type {resource_type} with logical name {resource.logical_name}..')
				parser.parse(resource.logical_name, resource.value)

		orphaned_policies = cls.get_orphaned_policies()

		return list(RoleParser.roles.values()), \
			list(UserParser.users.values()), \
			list(GroupParser.groups.values()), \
			list(PermissionSetParser.permission_sets.values()), \
			orphaned_policies

	@classmethod
	def get_orphaned_policies(cls):
		"""
		Orphaned policies are policies that are not attached to any principal
		"""
		role_policies = [policy for role in RoleParser.roles.values() for policy in role.Policies]
		user_policies = [policy for user in UserParser.users.values() for policy in user.Policies]
		group_policies = [policy for group in GroupParser.groups.values() for policy in group.Policies]
		permission_set_policies = [policy for permission_set in PermissionSetParser.permission_sets.values()
								   for policy in permission_set.Policies]

		all_attached_policies = list(set(role_policies) | set(user_policies) | set(group_policies) | set(permission_set_policies))
		all_managed_policies = list(ManagedPolicyParser.managed_policies.values())

		return [managed_policy for managed_policy in all_managed_policies if
				managed_policy not in all_attached_policies]


class AttachedPolicyParser:
	"""
	Handles parsing managed and inline policies from other resources
	"""
	def __init__(self, region):
		self.client = client.build('iam', region)

	@staticmethod
	def parse_inline_policies(principal, properties):
		inline_policies = properties.get('Policies', [])
		for inline_policy in inline_policies:
			policy_name = inline_policy['PolicyName']
			policy_document = inline_policy['PolicyDocument']

			policy = Policy(policy_name, policy_document)
			principal.add_policy(policy)

	def parse_managed_policies(self, principal, properties, property_name='ManagedPolicyArns'):
		managed_policy_arns = properties.get(property_name, [])
		for arn in managed_policy_arns:
			policy = ManagedPolicyParser.managed_policies.get(arn)
			if policy is not None:
				principal.add_policy(policy)
				continue

			try:
				# if the ARN is not a managed policy in the template, pull it from the environment
				response = self.client.get_policy(PolicyArn=arn)
			except ClientError as e:
				if e.response['Error']['Code'] == 'NoSuchEntity':
					raise ApplicationError(f'Could not find managed policy with {arn} in template or in environment.')
				else:
					raise

			policy_name = response['Policy']['PolicyName']
			default_version_id = response['Policy']['DefaultVersionId']
			policy_path = response['Policy']['Path']

			response = self.client.get_policy_version(PolicyArn=arn, VersionId=default_version_id)
			policy_document = response['PolicyVersion']['Document']

			policy = Policy(policy_name, policy_document, policy_path)
			principal.add_policy(policy)


class RoleParser:
	""" Parser for AWS::IAM::Role
	"""

	# store roles for the lifetime of the run for static lookup by other parsers
	roles = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		RoleParser.roles = {}

	@classmethod
	def get_role_by(cls, name):
		for role in cls.roles.values():
			if role.RoleName == name:
				return role

		# this means that it the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(roles_schema)

		properties = evaluated_resource['Properties']

		path = properties.get('Path', '/')
		trust_policy = properties['AssumeRolePolicyDocument']

		# if RoleName is not a property, use the resource name
		role_name = properties.get('RoleName', resource_name)

		role = Role(role_name, path, trust_policy)

		self.attached_policy_parser.parse_inline_policies(role, properties)
		self.attached_policy_parser.parse_managed_policies(role, properties)

		self.roles[resource_name] = role


class UserParser:
	""" AWS::IAM::User
	"""

	# store users for the lifetime of the run for static lookup by other parsers
	users = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		UserParser.users = {}

	@classmethod
	def get_user_by(cls, name):
		for user in cls.users.values():
			if user.UserName == name:
				return user

		# this means that it the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(users_schema)

		properties = evaluated_resource.get('Properties', {})

		path = properties.get('Path', '/')
		user_name = properties.get('UserName', resource_name)

		user = User(user_name, path)

		self.attached_policy_parser.parse_inline_policies(user, properties)
		self.attached_policy_parser.parse_managed_policies(user, properties)

		self.users[resource_name] = user


class GroupParser:
	""" AWS::IAM::Group
	"""

	# store groups for the lifetime of the run for static lookup by other parsers
	groups = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		GroupParser.groups = {}

	@classmethod
	def get_group_by(cls, name):
		for group in cls.groups.values():
			if group.GroupName == name:
				return group

		# this means that it the template is referencing a role external to the template,
		# but we still want to validate policies in the template
		return None

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(groups_schema)
		# there are no required properties for a group, so a group without properties is OK
		properties = evaluated_resource.get('Properties', {})

		path = properties.get('Path', '/')
		group_name = properties.get('GroupName', resource_name)

		group = Group(group_name, path)

		self.attached_policy_parser.parse_inline_policies(group, properties)
		self.attached_policy_parser.parse_managed_policies(group, properties)

		self.groups[resource_name] = group


class PermissionSetParser:
	""" Parser for AWS::SSO::PermissionSet
	"""

	permission_sets = {}

	def __init__(self, region):
		self.attached_policy_parser = AttachedPolicyParser(region)
		PermissionSetParser.permission_sets = {}

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(permission_set_schema)

		properties = evaluated_resource['Properties']

		name = properties['Name']

		permission_set = PermissionSet(name)

		self.parse_inline_policy(permission_set, properties)
		self.attached_policy_parser.parse_managed_policies(permission_set, properties, property_name="ManagedPolicies")

		self.permission_sets[resource_name] = permission_set

	@staticmethod
	def parse_inline_policy(permission_set, properties):
		""" PermissionSets can only have a single inline policy so the parsing logic is slightly different
		"""
		inline_policy = properties.get('InlinePolicy')
		if inline_policy is None:
			return

		policy = Policy('InlinePolicy', inline_policy)
		permission_set.add_policy(policy)


class PolicyParser(ABC):
	"""
	Base class for common policy (inline and managed) parsing
	"""

	@staticmethod
	def parse_roles(policy, properties):
		roles_to_apply_policy = properties.get('Roles', [])
		for role_name in roles_to_apply_policy:
			referenced_role = RoleParser.get_role_by(role_name)
			if referenced_role is not None:
				referenced_role.add_policy(policy)

	@staticmethod
	def parse_users(policy, properties):
		users_to_apply_policy = properties.get('Users', [])
		for user_name in users_to_apply_policy:
			referenced_user = UserParser.get_user_by(user_name)
			if referenced_user is not None:
				referenced_user.add_policy(policy)

	@staticmethod
	def parse_groups(policy, properties):
		groups_to_apply_policy = properties.get('Groups', [])
		for group_name in groups_to_apply_policy:
			referenced_group = GroupParser.get_group_by(group_name)
			if referenced_group is not None:
				referenced_group.add_policy(policy)


class InlinePolicyParser(PolicyParser):
	""" AWS::IAM::Policy
	"""

	def parse(self, _, resource):
		evaluated_resource = resource.eval(inline_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties['PolicyName']
		policy_document = properties['PolicyDocument']

		policy = Policy(policy_name, policy_document)

		self.parse_roles(policy, properties)
		self.parse_users(policy, properties)
		self.parse_groups(policy, properties)


class ManagedPolicyParser(PolicyParser):
	""" AWS::IAM::ManagedPolicy
	"""

	managed_policies = {}

	def __init__(self, account_config):
		super(ManagedPolicyParser, self).__init__()
		self.arn_generator = ArnGenerator(account_config)
		ManagedPolicyParser.managed_policies = {}

	def parse(self, resource_name, resource):
		evaluated_resource = resource.eval(managed_policy_schema)

		properties = evaluated_resource['Properties']

		policy_name = properties.get('ManagedPolicyName', resource_name)
		policy_document = properties['PolicyDocument']
		path = properties.get('Path', '/')

		policy = Policy(policy_name, policy_document, path)

		# attempt to see if this managed policy is attached to any roles, users or groups in the template
		self.parse_roles(policy, properties)
		self.parse_users(policy, properties)
		self.parse_groups(policy, properties)

		# generate an ARN to uniquely reference this managed policy since managed policy ARNs can also be referenced
		# from the principal side
		arn = self.arn_generator.try_generate_arn(policy_name, resource, 'Ref')
		self.managed_policies[arn] = policy
