"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
from cfn_policy_validator import client
from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.cfn_tools.schema_validator import validate_schema
from cfn_policy_validator.parsers.utils.cycle_detection import validate_no_cycle


def validate_fn_get_att_schema(value):
	validate_schema(value, get_att_schema, 'Fn::GetAtt')


class GetAttEvaluator:
	def __init__(self, resources, arn_generator, node_evaluator, region):
		self.resources = resources
		self.arn_generator = arn_generator
		self.node_evaluator = node_evaluator
		self.region = region
		self.custom_get_att_evals = {
			'AWS::CloudFront::CloudFrontOriginAccessIdentity': {
				'S3CanonicalUserId': get_canonical_user
			}
		}

	def evaluate(self, get_att_lookup, visited_values=None):
		if visited_values is None:
			visited_values = []

		validate_fn_get_att_schema(get_att_lookup)

		logical_name_of_resource = get_att_lookup[0]
		attribute_name = get_att_lookup[1]

		resource = self.resources.get(logical_name_of_resource)
		if resource is None:
			raise ApplicationError(f'Unable to find referenced resource for GetAtt reference to {logical_name_of_resource}.{attribute_name}')

		arn = self.arn_generator.try_generate_arn(logical_name_of_resource, resource, attribute_name, visited_values=visited_values)
		if arn is not None:
			return arn

		# if the GetAtt does not reference an ARN, see if we have a custom evaluation for this get_att.
		# Useful in cases where an attribute returns something other than an ARN that's relevant to
		# IAM policies (canonical username)
		custom_get_att_eval = self.custom_get_att_evals.get(resource['Type'], {}).get(attribute_name)
		if custom_get_att_eval is not None:
			return custom_get_att_eval(self.region)

		# For calls to GetAtt that are not ARNs, try to find a property with the same name.  This is a last resort and
		# should probably not occur often.  We expect to almost always see GetAtt used for ARNs in the context of an
		# IAM policy
		properties = resource.get('Properties', {})
		property_value = properties.get(attribute_name)
		if property_value is None:
			raise ApplicationError(f'Call to GetAtt not supported for: {logical_name_of_resource}.{attribute_name}')

		# we may need to traverse to another resource, so check to see if we've already done that and
		# we're stuck in a cycle
		validate_no_cycle(logical_name_of_resource, attribute_name, visited_values)

		# there are many return types for GetAtt, so it's the caller's responsibility to validate expected type
		return self.node_evaluator.eval(property_value, visited_values=visited_values)


# only look up the user id if it's requested
canonical_user_id = None


# Custom resolution of the canonical user which is a possible principal value for a policy
def get_canonical_user(region):
	global canonical_user_id
	if canonical_user_id is not None:
		return canonical_user_id

	s3_client = client.build('s3', region)
	response = s3_client.list_buckets()
	canonical_user_id = response['Owner']['ID']
	return canonical_user_id


get_att_schema = {
	'type': 'array',
	'items': [
		# only attribute name can contain references
		{'type': 'string'},
		{}
	],
	'additionalItems': False
}
