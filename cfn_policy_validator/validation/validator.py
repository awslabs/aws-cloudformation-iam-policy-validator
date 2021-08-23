"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import logging
import time

from cfn_policy_validator import client
from cfn_policy_validator.validation.findings import Findings
from cfn_policy_validator.validation import default_to_json
from cfn_policy_validator.validation.reporter import Reporter
from cfn_policy_validator.application_error import ApplicationError


LOGGER = logging.getLogger("cfn-policy-validator")


def validate(parser_output, findings_to_ignore, finding_types_that_are_errors, allowed_external_principals):
	"""
	Run the output from the parsers through IAM Access Analyzer, filter, and report the findings.
	"""

	findings = validate_parser_output(parser_output)

	reporter = Reporter(findings_to_ignore, finding_types_that_are_errors, allowed_external_principals)
	return reporter.build_report_from(findings)


def validate_parser_output(parser_output):
	"""
	Run the parser output through IAM Access Analyzer validation
	"""
	validator = Validator(parser_output.Account, parser_output.Region, parser_output.Partition)

	validator.validate_policies(parser_output.OrphanedPolicies)
	validator.validate_roles(parser_output.Roles)
	validator.validate_users(parser_output.Users)
	validator.validate_groups(parser_output.Groups)
	validator.validate_resources(parser_output.Resources)

	return validator.findings


class Validator:
	def __init__(self, account_id, region, partition):
		self.findings = Findings()
		self.access_analyzer_name = 'AnalyzerCreatedByCfnIAMPolicyValidator'
		self.analyzer_arn = None

		self.client = client.build('accessanalyzer', region)

		# config builders are used to build the access preview configuration for an individual resource type
		# a config builder must be added to add support for access previews for a resource
		self.config_builders = {
			'AWS::SQS::Queue': SqsQueueConfigurationBuilder(account_id, region, partition),
			'AWS::KMS::Key': KmsKeyConfigurationBuilder(account_id, region, partition),
			'AWS::S3::Bucket': S3BucketConfigurationBuilder(partition),
			'AWS::IAM::Role::TrustPolicy': RoleTrustPolicyConfigurationBuilder(account_id, partition),
			'AWS::SecretsManager::Secret': SecretsManagerSecretConfigurationBuilder(account_id, region, partition)
		}
		self.maximum_number_of_access_preview_attempts = 150

	def validate_roles(self, roles):
		"""
		Validate policies attached to roles
		"""
		self._try_create_analyzer()

		previews_to_await = []
		for role in roles:
			LOGGER.info(f'Validating trust policy for role {role.RoleName}..')
			response = self.client.validate_policy(
				policyType='RESOURCE_POLICY',
				policyDocument=json.dumps(role.TrustPolicy)
			)
			LOGGER.info(f'ValidatePolicy response: {response}')

			validation_findings = response['findings']
			self.findings.add_validation_finding(validation_findings, role.RoleName, 'TrustPolicy')

			# use access previews to validate a role's trust policy
			preview_id = self.__validate_role_trust_policy(role)
			preview = Preview(preview_id, role, role.RoleName, validation_findings)
			previews_to_await.append(preview)

			# validate identity policies attached to the role
			for policy in role.Policies:
				LOGGER.info(f'Validating identity policy for {role.RoleName} with name {policy.Name}')
				response = self.client.validate_policy(
					policyType='IDENTITY_POLICY',
					policyDocument=json.dumps(policy.Policy)
				)
				LOGGER.info(f'ValidatePolicy response: {response}')
				self.findings.add_validation_finding(response['findings'], role.RoleName, policy.Name)

		access_preview_findings = self._wait_for_findings(previews_to_await)
		for access_preview_finding in access_preview_findings:
			self.findings.add_trust_policy_finding(access_preview_finding.findings, access_preview_finding.resource.RoleName)

	def __validate_role_trust_policy(self, role):
		config_builder = self.config_builders['AWS::IAM::Role::TrustPolicy']
		configuration = config_builder.build_configuration(role)

		LOGGER.info(f'Creating access preview with configuration {configuration}')
		response = self.client.create_access_preview(
			analyzerArn=self.analyzer_arn,
			configurations=configuration
		)
		LOGGER.info(f'CreateAccessPreview response: {response}')
		return response['id']

	def validate_policies(self, policies):
		"""
		Validate orphaned policies
		"""
		resource_name = 'No resource attached'
		for policy in policies:
			LOGGER.info(f'Validating identity policy for {policy.Name}')
			response = self.client.validate_policy(
				policyType='IDENTITY_POLICY',
				policyDocument=json.dumps(policy.Policy)
			)
			LOGGER.info(f'ValidatePolicy response: {response}')
			self.findings.add_validation_finding(response['findings'], resource_name, policy.Name)

	def validate_users(self, users):
		"""
		Validate policies attached to users
		"""
		for user in users:
			for policy in user.Policies:
				LOGGER.info(f'Validating identity policy for user {user.UserName} with policy name {policy.Name}')
				response = self.client.validate_policy(
					policyType='IDENTITY_POLICY',
					policyDocument=json.dumps(policy.Policy)
				)
				LOGGER.info(f'ValidatePolicy response {response}')
				self.findings.add_validation_finding(response['findings'], user.UserName, policy.Name)

	def validate_groups(self, groups):
		"""
		Validate policies attached to groups
		"""
		for group in groups:
			for policy in group.Policies:
				LOGGER.info(f'Validating identity policy for group {group.GroupName} with policy name {policy.Name}')
				response = self.client.validate_policy(
					policyType='IDENTITY_POLICY',
					policyDocument=json.dumps(policy.Policy)
				)
				LOGGER.info(f'ValidatePolicy response {response}')
				self.findings.add_validation_finding(response['findings'], group.GroupName, policy.Name)

	def validate_resources(self, resources):
		"""
		Validate resource policies
		"""
		self._try_create_analyzer()

		previews_to_await = []
		for resource in resources:
			# we want to run validate_policy on all resource policies regardless of if they are supported policies
			# for access previews
			LOGGER.info(f'Validating resource policy for resource {resource.ResourceName} of type {resource.ResourceType}')
			response = self.client.validate_policy(
				policyType='RESOURCE_POLICY',
				policyDocument=json.dumps(resource.Policy.Policy)
			)
			LOGGER.info(f'ValidatePolicy response {response}')
			validation_findings = response['findings']
			self.findings.add_validation_finding(validation_findings, resource.ResourceName, resource.Policy.Name)

			# only supported policies for access previews will have config builders
			config_builder = self.config_builders.get(resource.ResourceType)
			if config_builder is not None:
				configuration = config_builder.build_configuration(resource)

				LOGGER.info(f'Creating access preview for resource {resource.ResourceName} of type {resource.ResourceType}')
				LOGGER.info(f'Using access preview configuration: {configuration}')
				response = self.client.create_access_preview(
					analyzerArn=self.analyzer_arn,
					configurations=configuration
				)
				LOGGER.info(f'CreateAccessPreview response: {response}')
				preview = Preview(response['id'], resource, resource.ResourceName, validation_findings)
				previews_to_await.append(preview)

		# batch and wait for all access previews to complete
		access_preview_findings = self._wait_for_findings(previews_to_await)

		for access_preview_finding in access_preview_findings:
			self.findings.add_external_principal_finding(access_preview_finding.findings,
														 access_preview_finding.resource.ResourceName,
														 access_preview_finding.resource.Policy.Name)

	def _wait_for_findings(self, previews_to_await):
		findings = []
		for preview in previews_to_await:
			number_of_attempts = 0
			while True:
				LOGGER.info(f'Waiting on access preview {preview.id} to finish creating attempt {number_of_attempts+1}..')
				response = self.client.get_access_preview(
					accessPreviewId=preview.id,
					analyzerArn=self.analyzer_arn
				)
				LOGGER.info(f'GetAccessPreview response: {response}')
				status = response['accessPreview']['status']

				if status == 'CREATING':
					number_of_attempts = number_of_attempts + 1
					if number_of_attempts >= self.maximum_number_of_access_preview_attempts:
						raise ApplicationError(f'Timed out after 5 minutes waiting for access analyzer preview to create.')

					time.sleep(2)
				else:
					break

			LOGGER.info(f'Access preview creation completed for {preview.name} with status {status}')

			if status == 'FAILED':
				reason = response["accessPreview"]["statusReason"]["code"]
				if reason == 'INVALID_CONFIGURATION':
					self._raise_invalid_configuration_error_for(preview)

				raise ApplicationError(f'Failed to create access preview for {preview.name}.  Reason: {reason}')

			paginator = self.client.get_paginator('list_access_preview_findings')
			for page in paginator.paginate(accessPreviewId=preview.id, analyzerArn=self.analyzer_arn):
				findings.append(AccessPreviewFindings(preview.resource, page['findings']))

		return findings

	def _try_create_analyzer(self):
		if self.analyzer_arn is not None:
			return

		response = self.client.list_analyzers(
			type='ACCOUNT'
		)

		first_active_analyzer = next((analyzer for analyzer in response['analyzers'] if analyzer['status'] == 'ACTIVE'), None)
		if first_active_analyzer is not None:
			self.analyzer_arn = first_active_analyzer['arn']
			return

		LOGGER.info('No active analyzers found in account.  Creating analyzer.')
		response = self.client.create_analyzer(
			analyzerName=self.access_analyzer_name,
			type='ACCOUNT'
		)
		self.analyzer_arn = response['arn']

	@staticmethod
	def _raise_invalid_configuration_error_for(preview):
		# if we get an invalid configuration error, surface the validation findings as they likely point
		# to the issue
		message = f'Failed to create access preview for {preview.name}.  Validate that your trust or resource policy\'s ' \
				  f'schema is correct.'
		if len(preview.validation_findings) > 0:
			message += f'\nThe following validation findings were detected for this resource: ' \
					   f'{json.dumps(preview.validation_findings, default=default_to_json, indent=4)}.'

		raise ApplicationError(message)


class AccessPreviewFindings:
	def __init__(self, resource, findings):
		self.resource = resource
		self.findings = findings


class Preview:
	def __init__(self, preview_id, resource, name, validation_findings):
		self.id = preview_id
		self.resource = resource
		self.name = name
		self.validation_findings = validation_findings


class SqsQueueConfigurationBuilder:
	def __init__(self, account_id, region, partition):
		self.region = region
		self.account_id = account_id
		self.partition = partition

	def build_configuration(self, resource):
		policy = json.dumps(resource.Policy.Policy)

		return {
			f'arn:{self.partition}:sqs:{self.region}:{self.account_id}:{resource.ResourceName}': {
				'sqsQueue': {
					'queuePolicy': policy
				}
			}
		}


class KmsKeyConfigurationBuilder:
	def __init__(self, account_id, region, partition):
		self.account_id = account_id
		self.region = region
		self.partition = partition

	def build_configuration(self, resource):
		policy = json.dumps(resource.Policy.Policy)

		return {
			f'arn:{self.partition}:kms:{self.region}:{self.account_id}:key/{resource.ResourceName}': {
				'kmsKey': {
					'keyPolicies': {
						'default': policy
					}
				}
			}
		}


class S3BucketConfigurationBuilder:
	def __init__(self, partition):
		self.partition = partition

	def build_configuration(self, resource):
		policy = json.dumps(resource.Policy.Policy)

		return {
			f'arn:{self.partition}:s3:::{resource.ResourceName}': {
				's3Bucket': {
					'bucketPolicy': policy
				}
			}
		}


class RoleTrustPolicyConfigurationBuilder:
	def __init__(self, account_id, partition):
		self.account_id = account_id
		self.partition = partition

	def build_configuration(self, resource):
		policy = json.dumps(resource.TrustPolicy)

		return {
			f'arn:{self.partition}:iam::{self.account_id}:role/{resource.RoleName}': {
				'iamRole': {
					'trustPolicy': policy
				}
			}
		}


class SecretsManagerSecretConfigurationBuilder:
	def __init__(self, account_id, region, partition):
		self.account_id = account_id
		self.region = region
		self.partition = partition

	def build_configuration(self, resource):
		policy = json.dumps(resource.Policy.Policy)

		return {
			# secrets manager arns have a random 6 characters appended to the end
			f'arn:{self.partition}:secretsmanager:{self.region}:{self.account_id}:secret:{resource.ResourceName}-3xyxqI': {
				'secretsManagerSecret': {
					'secretPolicy': policy
				}
			}
		}
