"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
from botocore.exceptions import ClientError

from cfn_policy_validator.validation.findings import Findings
from cfn_policy_validator.validation.reporter import Reporter
from cfn_policy_validator.application_error import ApplicationError

from cfn_policy_validator.canonical_user_id import client
from cfn_policy_validator.parsers.output import Output, PermissionSet, Role, User, Group

LOGGER = logging.getLogger("cfn-policy-validator")

RESOURCE_POLICY_TYPE = 'RESOURCE_POLICY'
IDENTITY_POLICY_TYPE = 'IDENTITY_POLICY'

policy_analysis_prefix = 'policy-analysis-'

ACTIONS_MAX_ITEMS = 100
RESOURCES_MAX_ITEMS = 100

CHECK_NO_PUBLIC_ACCESS_SUPPORTED_TYPES = {
	"AWS::KMS::Key",
	"AWS::Lambda::Function",
	"AWS::S3::Bucket",
	"AWS::S3::AccessPoint",
	"AWS::SecretsManager::Secret",
	"AWS::SNS::Topic",
	"AWS::SQS::Queue",
	"AWS::IAM::AssumeRolePolicyDocument"	
}

def get_identity_resource_name(resource):
	if isinstance(resource, PermissionSet):
		return resource.Name
	if isinstance(resource, User):
		return resource.UserName
	if isinstance(resource, Group):
		return resource.GroupName
	if isinstance(resource, Role):
		return resource.RoleName
	
def get_identity_resource_type_name(resource):
	if isinstance(resource, PermissionSet):
		return "permission set"
	if isinstance(resource, User):
		return "user"
	if isinstance(resource, Group):
		return "group"
	if isinstance(resource, Role):
		return "role"

class PolicyAnalysis:
	def __init__(self, region):
		self.findings = Findings()
		self.identity_policy_cache = {}
		self.resource_policy_cache = {}
		self.client = client.build('accessanalyzer', region)
	
	def _handle_response(self, response, resource_name, policy_name, operation_name):
		"""
		Builds a list of raw findings based on the API response
		"""
		# check-access passes in a list as it does batching and calling for more than 50 actions
		if isinstance(response, list):
			findings = [self._build_policy_analysis_finding(r, operation_name) for r in response if r.get('result') != 'PASS']
		elif response.get('result') != 'PASS':
			findings = [self._build_policy_analysis_finding(response, operation_name)]
		else:
			findings = []
		self.findings.add_policy_analysis_finding(findings, resource_name, policy_name, operation_name)
	
	def _build_policy_analysis_finding(self, response, operation_name):
		"""
		Create a raw finding for non 'PASS' results
		"""
		code = f'{policy_analysis_prefix}{operation_name}'
		response_code = response['ResponseMetadata']['HTTPStatusCode']
		if response_code != 200:
			# error response shape https://boto3.amazonaws.com/v1/documentation/api/latest/guide/error-handling.html
			# response['Error']['Code'] returns literal exception name such as ValidationException, UnprocessableEntityException
			# Raise error for non 400 errors
			if (response_code < 400 or response_code > 499):
				raise ApplicationError(response.get('message'))
			# Add finding for 400 errors
			else:
				exceptionName = response['Error']['Code']
				code += response['Error']['Code']
				finding_type = "ERROR"	
		else:
			finding_type = "SECURITY_WARNING"
		response_no_metadata = response.copy()
		del response_no_metadata['ResponseMetadata']
		rawFinding = {
			'message': response.get('message'), 
			'findingType': finding_type,
			'response': response_no_metadata,
			'code': code
		}
		return rawFinding

	
	def check_identity(self, parser_output: Output):
		"""
		check identity policies
		"""
		# parser_output.PermissionSets, parser_output.Users, parser_output.Roles and parser_output.Group are array of PermissionSet,
		# array of User, array of Role and array of Group, all these objects inherit from the same base IdentityWithPolicies class

		for identity_resources in [parser_output.PermissionSets, parser_output.Users, parser_output.Roles, parser_output.Groups]:
			for identity_resource in identity_resources:
				for policy in identity_resource.Policies:
						policy_str = json.dumps(policy.Policy)
						identity_resource_type_name = get_identity_resource_type_name(identity_resource)
						identity_resource_name = get_identity_resource_name(identity_resource)
						# if this identity policy has not been run against the check(not in the cache)
						if policy_str not in self.identity_policy_cache:
							LOGGER.info(f'Checking identity policy for {identity_resource_type_name} {identity_resource_name} with policy name {policy.Name}')
							response = self._call_api(policy.Policy, IDENTITY_POLICY_TYPE, policy.IsAWSManagedPolicy)
							LOGGER.info(f'{self.operation_name} response {response}')
							self.identity_policy_cache[policy_str] = response
						else:
							LOGGER.info(f'Identity policy for {identity_resource_type_name} {identity_resource_name} with policy name {policy.Name} already checked. Skipped.')
							response = self.identity_policy_cache.get(policy_str)
						self._handle_response(response, identity_resource_name, policy.Name, self.operation_name)

	def check_resources(self, resources, roles):
		"""
		check resource policies
		"""
		# for resource in resources
		for resource in resources:
			if resource.Policy.Policy is None:
				LOGGER.info(f'Resource {resource.ResourceName} has no resource-based policy.  Skipping call to {self.operation_name}.')
			else:
				policy_str = json.dumps(resource.Policy.Policy)
				# if this resource policy has not been run against the check(not in the cache)
				if policy_str not in self.resource_policy_cache:
					LOGGER.info(f'Check policy for resource {resource.ResourceName} of type {resource.ResourceType}')
					response = self._call_api(resource.Policy.Policy, RESOURCE_POLICY_TYPE, False)
					LOGGER.info(f'{self.operation_name} response {response}')
					self.resource_policy_cache[policy_str] = response
				else:
					LOGGER.info(f'Resource policy for {resource.ResourceName} of type {resource.ResourceType} already checked. Skipped.')
					response = self.resource_policy_cache.get(policy_str)
				self._handle_response(response, resource.ResourceName, resource.Policy.Name, self.operation_name)
		# Trust policies are resource policies but are attached to roles
		for role in roles:
			if not role.TrustPolicy:
				raise ApplicationError(f'Unable to find trust policy for {role.RoleName}')
			else:
				policy_str = json.dumps(role.TrustPolicy)
				if policy_str not in self.resource_policy_cache:
					LOGGER.info(f'Check trust policy for role {role.RoleName}')
					response = self._call_api(role.TrustPolicy, RESOURCE_POLICY_TYPE, False)
					self.resource_policy_cache[policy_str] = response
				else:
					LOGGER.info(f'Trust policy for role {role.RoleName} already checked. Skipped.')
					response = self.resource_policy_cache.get(policy_str)
				self._handle_response(response, role.RoleName, 'TrustPolicy', self.operation_name)

	def _call_api(self, policy_as_json, policy_type, is_aws_managed_policy):
		pass

def compare(parser_output, reference_policy, reference_policy_type, ignore_finding, findings_are_blocking):
	"""
	Run the output from the parsers through IAM Access Analyzer, filter, and report the results.
	"""

	findings = compare_parser_output(parser_output, reference_policy, reference_policy_type)

	finding_types_that_are_blocking = ["SECURITY_WARNING", "ERROR"]
	if not findings_are_blocking:
		finding_types_that_are_blocking = ["None"]

	reporter = Reporter(ignore_finding, finding_types_that_are_blocking, None)
	return reporter.build_report_from(findings)


def compare_parser_output(parser_output, reference_policy, reference_policy_type):
	"""
	Run the parser output through IAM Access Analyzer validation
	"""
	comparator = Comparator(parser_output.Region, reference_policy)
	if reference_policy_type.lower() == "identity":
		comparator.check_identity(parser_output)
	elif reference_policy_type.lower() == "resource":
		comparator.check_resources(parser_output.Resources, parser_output.Roles)
	else:
		raise ApplicationError("Invalid reference policy type specified. Please specify 'identity' or 'resource'")

	return comparator.findings

class Comparator(PolicyAnalysis):

	def __init__(self, region, reference_policy):
		PolicyAnalysis.__init__(self, region)
		self.reference_policy = reference_policy
		self.operation_name = "CheckNoNewAccess"

	def _call_api(self, policy_as_json, policy_type, is_aws_managed_policy):
		policy_as_string = json.dumps(policy_as_json)

		try:
			response = self.client.check_no_new_access(
				policyType=policy_type,
				existingPolicyDocument=self.reference_policy,
				newPolicyDocument=policy_as_string,
			)
		except ClientError as error:
			return error.response

		return response

def check_access(parser_output, ignore_finding, findings_are_blocking, actions=[], resources=[]):
	"""
	Run the output from the parsers through IAM Access Analyzer, filter, and report the results.
	"""

	findings = check_access_parser_output(parser_output, actions, resources)

	finding_types_that_are_blocking = ["SECURITY_WARNING", "ERROR"]
	if not findings_are_blocking:
		finding_types_that_are_blocking = ["None"]

	reporter = Reporter(ignore_finding, finding_types_that_are_blocking, None)
	return reporter.build_report_from(findings)


def check_access_parser_output(parser_output, actions, resources):
	"""
	Run the parser output through IAM Access Analyzer validation
	"""
	access_checker = AccessChecker(parser_output.Region, actions, resources)

	access_checker.check_identity(parser_output)
	access_checker.check_resources(parser_output.Resources, parser_output.Roles)
	return access_checker.findings

class AccessChecker(PolicyAnalysis):

	def __init__(self, region, actions=[], resources=[]):
		PolicyAnalysis.__init__(self, region)
		self.accesses = []

		if actions:
			for i in range (0, len(actions), ACTIONS_MAX_ITEMS):
				access = [self.create_access(actions, resources)]
				self.accesses.append(access)
		elif resources:
			self.accesses.append([self.create_access(actions, resources)])
		self.operation_name = "CheckAccessNotGranted"

	def create_access(self, actions, resources):
		access = {}
		if actions:
			access["actions"] = actions
		if resources:
			if len(resources) > RESOURCES_MAX_ITEMS:
				raise ApplicationError("Too many resource ARNs were specified. You may only specify up to 100 resource ARNs.")
			access["resources"] = resources
		return access

	def _call_api(self, policy_as_json, policy_type, is_aws_managed_policy):
		policy_as_string = json.dumps(policy_as_json)
		responses = []
		failed_response = {
			"result": "FAIL",
			"reasons": []
		}
		for access in self.accesses:
			LOGGER.info(f'Batching actions {access}')
			try:
				response = self.client.check_access_not_granted(
					policyType=policy_type,
					policyDocument=policy_as_string,
					access=access
				)
			except ClientError as error:
				response = error.response
			if response.get('result') == 'FAIL':
				failed_response["message"] = response.get('message')
				reasons = response.get('reasons')
				if reasons is not None:
					for r in reasons:
						r['accessInput'] = access
					failed_response['reasons'].extend(reasons)
				else:
					failed_response['reasons'].append({
						'accessInput': access
					})
				failed_response['ResponseMetadata'] = response['ResponseMetadata']
			else:
				response['accessInput'] = access
				responses.append(response)
		if failed_response.get('ResponseMetadata') is not None: # There were failed checks
			responses.append(failed_response)
		return responses

def check_no_public_access(parser_output, ignore_finding, findings_are_blocking):
	"""
	Run the output from the parsers through IAM Access Analyzer, filter, and report the results.
	"""

	public_access_checker = PublicAccessChecker(parser_output.Region)
	public_access_checker.check_resources(parser_output.Resources, parser_output.Roles)
	findings = public_access_checker.findings

	finding_types_that_are_blocking = ["SECURITY_WARNING", "ERROR"]
	if not findings_are_blocking:
		finding_types_that_are_blocking = ["None"]

	reporter = Reporter(ignore_finding, finding_types_that_are_blocking, None)
	return reporter.build_report_from(findings)

class PublicAccessChecker(PolicyAnalysis):

	def __init__(self, region):
		PolicyAnalysis.__init__(self, region)
		self.operation_name = "CheckNoPublicAccess"

	def _call_api(self, policy_as_json, policy_type, resource_type):
		policy_as_string = json.dumps(policy_as_json)

		try:
			response = self.client.check_no_public_access(
				policyDocument=policy_as_string,
				resourceType=resource_type,
			)
		except ClientError as error:
			return error.response

		return response

	def check_resources(self, resources, roles):
		"""
		Check resource policies of types supported by CheckNoPublicAccess
		"""
		for resource in resources:
			# Check if this is a supported resource type, otherwise skip
			if resource.ResourceType not in CHECK_NO_PUBLIC_ACCESS_SUPPORTED_TYPES:
				LOGGER.info(f'CheckNoPublicAccess does not support {resource.ResourceType}, skipping check.')
				continue
			elif resource.Policy.Policy is None:
				LOGGER.info(f'Resource {resource.ResourceName} has no resource-based policy.  Skipping call to {self.operation_name}.')
			else:
				policy_str = json.dumps(resource.Policy.Policy)
				# if this resource policy has not been run against the check(not in the cache)
				if (policy_str, resource.ResourceType) not in self.resource_policy_cache:
					LOGGER.info(f'Check policy for resource {resource.ResourceName} of type {resource.ResourceType}')
					response = self._call_api(resource.Policy.Policy, RESOURCE_POLICY_TYPE, resource.ResourceType)
					LOGGER.info(f'{self.operation_name} response {response}')
					self.resource_policy_cache[(policy_str, resource.ResourceType)] = response
				else:
					LOGGER.info(f'Resource policy for {resource.ResourceName} of type {resource.ResourceType} already checked. Skipped.')
					response = self.resource_policy_cache.get((policy_str, resource.ResourceType))
				self._handle_response(response, resource.ResourceName, resource.Policy.Name, self.operation_name)
		# Trust policies are resource policies but are attached to roles
		for role in roles:
			if not role.TrustPolicy:
				raise ApplicationError(f'Unable to find trust policy for {role.RoleName}')
			else:
				policy_str = json.dumps(role.TrustPolicy)
				if (policy_str, resource.ResourceType) not in self.resource_policy_cache:
					LOGGER.info(f'Check trust policy for role {role.RoleName}')
					response = self._call_api(role.TrustPolicy, RESOURCE_POLICY_TYPE, "AWS::IAM::AssumeRolePolicyDocument")
					LOGGER.info(f'{self.operation_name} response {response}')
					self.resource_policy_cache[(policy_str, resource.ResourceType)] = response
				else:
					LOGGER.info(f'Trust policy for role {role.RoleName} already checked. Skipped.')
					response = self.resource_policy_cache.get((policy_str, resource.ResourceType))
				self._handle_response(response, role.RoleName, 'TrustPolicy', self.operation_name)
