"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import json
import os

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema
from cfn_policy_validator.parsers.utils.cycle_detection import validate_no_cycle
from cfn_policy_validator.parsers.utils.intrinsic_functions import name_hints
from cfn_policy_validator.parsers.utils.intrinsic_functions import aws_url_suffix_evaluator
from cfn_policy_validator.parsers.utils.intrinsic_functions.aws_no_value_evaluator import NoValue


class RefEvaluator:
	def __init__(self, resources, arn_generator, parameters, parameter_values, account_config, node_evaluator):
		this_files_directory = os.path.dirname(os.path.realpath(__file__))
		with open(os.path.join(this_files_directory, '..', 'services_where_ref_returns_arn.json')) as f:
			services_where_ref_returns_arn = json.load(f)

		self.services_where_ref_returns_arn = services_where_ref_returns_arn['Resources']
		self.resources = resources
		self.arn_generator = arn_generator
		self.parameters = parameters
		self.parameter_values = parameter_values
		self.account_config = account_config
		self.node_evaluator = node_evaluator

		# some resources require custom evaluation logic, but we should only need to care about this for resources that
		# have resource policies that we want to parse
		self.custom_ref_evals = {
			'AWS::SQS::Queue': evaluate_sqs_queue_ref
		}

	def evaluate(self, resource_logical_name_or_param, visited_values=None):
		""" Evaluates a Fn::Ref function
			visited_values: tracks visited values to detect circular references in a CloudFormation template
		"""
		if visited_values is None:
			visited_values = []

		validate_schema(resource_logical_name_or_param, ref_schema, 'Ref')

		if resource_logical_name_or_param == "AWS::AccountId":
			return self.account_config.account_id

		if resource_logical_name_or_param == "AWS::Partition":
			return self.account_config.partition

		if resource_logical_name_or_param == "AWS::Region":
			return self.account_config.region

		if resource_logical_name_or_param == "AWS::StackName":
			# just return some default value, we won't know this in advance
			return "StackName"

		if resource_logical_name_or_param == "AWS::NoValue":
			return NoValue()

		if resource_logical_name_or_param == "AWS::URLSuffix":
			return aws_url_suffix_evaluator.evaluate(self.account_config.region)

		# check to see if the reference is for a resource
		resource = self.resources.get(resource_logical_name_or_param)
		if resource is not None:
			resource_type = resource['Type']

			# first, see if this ref should return an ARN.  Not all Ref's return ARNs.
			if resource_type in self.services_where_ref_returns_arn:
				return self.arn_generator.try_generate_arn(resource_logical_name_or_param, resource, 'Ref', visited_values=visited_values)

			# next, see if we have a custom evaluation for this ref
			custom_ref_eval = self.custom_ref_evals.get(resource_type)
			if custom_ref_eval is not None:
				return custom_ref_eval(resource_logical_name_or_param, resource, self.account_config, visited_values)

			# at this point, we make the assumption that the resource just returns a string (probably either the resource
			# name or ID)
			properties = resource.get('Properties', {})

			# next, attempt to return the actual name of the resource if one is defined and it's for a common resource
			name_returned_by_ref = name_hints.get(resource_type)
			property_value = properties.get(name_returned_by_ref)
			if property_value is None:
				# just return the CFN logical name if there's no property to be found
				return resource_logical_name_or_param

			# we found a valid property value for the name of the resources. this property may reference another resource,
			# so check to see if we've already done that and we're stuck in a cycle
			validate_no_cycle(resource_logical_name_or_param, name_returned_by_ref, visited_values)
			return self.node_evaluator.eval(property_value, visited_values=visited_values)

		# if it's not a reference to a resource, check to see if it references a parameter
		parameter = self.parameters.get(resource_logical_name_or_param)
		if parameter is not None:
			# if the parameter exists in the template, make sure a value was passed in for it
			parameter_value = self.parameter_values.get(resource_logical_name_or_param)
			if parameter_value is None:
				raise ApplicationError(f'No value passed for referenced parameter: {resource_logical_name_or_param}.\n'
									   f'Parameters are passed using the --parameters flag.')

			return parameter_value

		raise ApplicationError(f'Unable to find a referenced resource or parameter in template: {resource_logical_name_or_param}')


# used to map common CFN resource types to their name properties to more accurately generate names for common resources
# instead of defaulting to the CFN resource's logical name
# this is a user experience improvement and does not impact the validation / analysis of policies
ref_name_hints = {
	'AWS::S3::Bucket': 'BucketName',
	'AWS::Lambda::Function': 'FunctionName',
	'AWS::IAM::Role': 'RoleName',
	'AWS::IAM::User': 'UserName',
	'AWS::IAM::Group': 'GroupName',
	'AWS::SQS::Queue': 'QueueName'
}


ref_schema = {
	'type': 'string'
}


# for SQS, we need to know that Ref returns a queue URL.  This queue URL is used to link the queue's policy to the queue
def evaluate_sqs_queue_ref(resource_name, sqs_queue_resource, account_config, visited_values):
	evaluated_resource = sqs_queue_resource.eval(sqs_queue_schema, visited_values)

	properties = evaluated_resource.get('Properties', {})
	queue_name = properties.get('QueueName', resource_name)

	return f'https://sqs.{account_config.region}.amazonaws.com/{account_config.account_id}/{queue_name}'


sqs_queue_schema = {
	'type': 'object',
	'properties': {
		'Properties': {
			'type': 'object',
			'properties': {
				'QueueName': {
					'type': 'string'
				}
			}
		}
	}
}
