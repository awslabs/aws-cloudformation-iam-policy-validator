import uuid
from datetime import datetime
from unittest.mock import ANY

from cfn_policy_validator.tests.boto_mocks import mock_test_setup, BotoResponse, BotoClientError

analyzer_arn = 'arn:aws:access-analyzer:us-east-1:111222333444:analyzer/MyAnalyzer'


role_trust_policy_expected_params_validate_policy = {
	'policyType': 'RESOURCE_POLICY',
	'policyDocument': ANY,
	'validatePolicyResourceType': 'AWS::IAM::AssumeRolePolicyDocument'
}


def mock_access_analyzer_resource_setup(*mock_validation_results):
	return mock_test_setup(
		accessanalyzer=[
			validate_resources(*mock_validation_results)
		]
	)


def mock_access_analyzer_identity_setup(*mock_validation_results):
	return mock_test_setup(
		accessanalyzer=[
			validate_identities(*mock_validation_results)
		]
	)

def mock_access_analyzer_role_setup(*mock_validation_results):
	return mock_test_setup(
		accessanalyzer=[
			validate_roles(*mock_validation_results)
		]
	)


def use_existing_analyzer():
	return BotoResponse(
		method='list_analyzers',
		service_response={
			'analyzers': [
				{
					'arn': analyzer_arn,
					'status': 'ACTIVE',
					'createdAt': datetime(2015, 1, 1),
					'name': 'MyAnalyzer',
					'type': 'ACCOUNT'
				}
			]
		}
	)


class FINDING_TYPE:
	SUGGESTION = 'SUGGESTION'
	ERROR = 'ERROR'
	SECURITY_WARNING = 'SECURITY_WARNING'
	WARNING = 'WARNING'


class MockValidationResult:
	def __init__(self, expected_params_create_access_preview=None, expected_params_validate_policy=None):
		self.expected_params_create_access_preview = expected_params_create_access_preview
		self.expected_params_validate_policy = expected_params_validate_policy

	def get_validate_resource_policy_response(self):
		expected_params = self.__get_expected_params_for_validate_policy('RESOURCE_POLICY')

		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': []
			},
			expected_params=expected_params
		)

	def get_validate_identity_policy_response(self):
		expected_params = self.__get_expected_params_for_validate_policy('IDENTITY_POLICY')

		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': []
			},
			expected_params=expected_params
		)

	def get_create_access_preview_response(self, access_preview_id):
		return BotoResponse(
			method='create_access_preview',
			service_response={
				'id': access_preview_id
			},
			expected_params=self.expected_params_create_access_preview
		)

	def get_get_access_preview_response(self, access_preview_id):
		return BotoResponse(
			method='get_access_preview',
			service_response={
				'accessPreview': {
					'id': access_preview_id,
					'analyzerArn': analyzer_arn,
					'createdAt': datetime(2015, 1, 1),
					'configurations': {},
					'status': 'COMPLETED'
				}
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)

	def get_list_access_preview_findings_response(self, access_preview_id):
		return BotoResponse(
			method='list_access_preview_findings',
			service_response={
				'findings': []
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)

	def __get_expected_params_for_validate_policy(self, default_policy_type):
		if self.expected_params_validate_policy is None or \
				self.expected_params_validate_policy['policyType'] != default_policy_type:
			return {
				'policyType': default_policy_type,
				'policyDocument': ANY
			}
		else:
			return self.expected_params_validate_policy

	@staticmethod
	def build_expected_validate_policy_params(custom_validate_policy_type, policy_type='RESOURCE_POLICY'):
		if custom_validate_policy_type is None:
			return None

		return {
			'policyType': policy_type,
			'policyDocument': ANY,
			'validatePolicyResourceType': custom_validate_policy_type
		}


class MockAccessPreviewFinding(MockValidationResult):
	def __init__(self, source_type=None, custom_validate_policy_type=None, finding_status='ACTIVE'):
		self.source_type = source_type
		self.finding_status = finding_status

		expected_params_validate_policy = self.build_expected_validate_policy_params(custom_validate_policy_type)
		super(MockAccessPreviewFinding, self).__init__(expected_params_validate_policy=expected_params_validate_policy)

	def get_list_access_preview_findings_response(self, access_preview_id):
		response = BotoResponse(
			method='list_access_preview_findings',
			service_response={
				'findings':  [{
					'createdAt': datetime(2015, 1, 1),
					'id': str(uuid.uuid4()),
					'resourceOwnerAccount': '1111222233334444',
					'resourceType': 'AWS::IAM::Role',  # type is ignored, but is required
					'status': self.finding_status,
					'changeType': 'NEW'
				}]
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)

		if self.source_type is not None:
			response.service_response['findings'][0]['sources'] = [{'type': self.source_type}]

		return response


class MockAccessPreviewFindingOnly(MockAccessPreviewFinding):
	# mocks an access preview finding, but skips validate policy
	def __init__(self, source_type=None):
		self.source_type = source_type
		super(MockAccessPreviewFindingOnly, self).__init__()

	def get_validate_resource_policy_response(self):
		return None

	def get_validate_identity_policy_response(self):
		return None


class MockValidateResourcePolicyFinding(MockValidationResult):
	def __init__(self, code, finding_type='ERROR', custom_resource_type=None):
		super(MockValidateResourcePolicyFinding, self).__init__()
		self.code = code
		self.finding_type = finding_type
		self.custom_resource_type = custom_resource_type

	def get_validate_resource_policy_response(self):
		expected_params = {
			'policyType': 'RESOURCE_POLICY',
			'policyDocument': ANY
		}

		if self.custom_resource_type is not None:
			expected_params['validatePolicyResourceType'] = self.custom_resource_type

		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': [{
					'issueCode': self.code,
					'findingDetails': 'details',
					'findingType': self.finding_type,
					'learnMoreLink': 'link',
					'locations': []
				}]
			},
			expected_params=expected_params
		)


class MockValidateIdentityPolicyFinding(MockValidationResult):
	def __init__(self, code, finding_type='ERROR', has_next_token_in_response=False, has_next_token_in_request=False):
		super(MockValidateIdentityPolicyFinding, self).__init__(
			expected_params_validate_policy=role_trust_policy_expected_params_validate_policy
		)
		self.code = code
		self.finding_type = finding_type
		self.has_next_token_in_response = has_next_token_in_response
		self.has_next_token_in_request = has_next_token_in_request
		self.next_token_value = 'abc123'

	def get_validate_identity_policy_response(self):
		response = {
			'findings': [{
				'issueCode': self.code,
				'findingDetails': 'details',
				'findingType': self.finding_type,
				'learnMoreLink': 'link',
				'locations': []
			}]
		}

		if self.has_next_token_in_response:
			response['nextToken'] = self.next_token_value

		expected_params = {
			'policyType': 'IDENTITY_POLICY',
			'policyDocument': ANY
		}

		if self.has_next_token_in_request:
			expected_params['nextToken'] = self.next_token_value

		return BotoResponse(
			method='validate_policy',
			service_response=response,
			expected_params=expected_params
		)


class MockValidateIdentityAndResourcePolicyFinding(MockValidationResult):
	def __init__(self, resource_code, resource_finding_type, identity_code, identity_finding_type, custom_resource_type):
		super(MockValidateIdentityAndResourcePolicyFinding, self).__init__()
		self.mock_validate_resource_policy_finding = MockValidateResourcePolicyFinding(resource_code, resource_finding_type, custom_resource_type)
		self.mock_validate_identity_policy_finding = MockValidateIdentityPolicyFinding(identity_code, identity_finding_type)

	def get_validate_identity_policy_response(self):
		return self.mock_validate_identity_policy_finding.get_validate_identity_policy_response()

	def get_validate_resource_policy_response(self):
		return self.mock_validate_resource_policy_finding.get_validate_resource_policy_response()


class MockNoFindings(MockValidationResult):
	def __init__(self, expected_params_create_access_preview=None, custom_validate_policy_type=None):
		expected_params_validate_policy = self.build_expected_validate_policy_params(custom_validate_policy_type)
		super(MockNoFindings, self).__init__(expected_params_create_access_preview, expected_params_validate_policy)


class MockNoFindingsAccessPreviewOnly(MockNoFindings):
	def __init__(self, custom_validate_policy_type=None):
		super(MockNoFindingsAccessPreviewOnly, self).__init__(custom_validate_policy_type)

	def get_validate_identity_policy_response(self):
		return None

	def get_validate_resource_policy_response(self):
		return None


class MockUnknownError(MockValidationResult):
	def __init__(self, expected_params_create_access_preview=None, custom_validate_policy_type=None):
		expected_params_validate_policy = self.build_expected_validate_policy_params(custom_validate_policy_type)
		super(MockUnknownError, self).__init__(expected_params_create_access_preview, expected_params_validate_policy)

	def get_get_access_preview_response(self, access_preview_id):
		return BotoResponse(
			method='get_access_preview',
			service_response={
				'accessPreview': {
					'id': access_preview_id,
					'analyzerArn': analyzer_arn,
					'createdAt': datetime(2015, 1, 1),
					'configurations': {},
					'status': 'FAILED',
					'statusReason': {
						'code': 'UNKNOWN_ERROR'
					}
				}
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)


class MockTimeout(MockValidationResult):
	def __init__(self, expected_params_create_access_preview=None, custom_validate_policy_type=None):
		expected_params_validate_policy = self.build_expected_validate_policy_params(custom_validate_policy_type)
		super(MockTimeout, self).__init__(expected_params_create_access_preview, expected_params_validate_policy)

	def get_get_access_preview_response(self, access_preview_id):
		return [BotoResponse(
			method='get_access_preview',
			service_response={
				'accessPreview': {
					'id': access_preview_id,
					'analyzerArn': analyzer_arn,
					'createdAt': datetime(2015, 1, 1),
					'configurations': {},
					'status': 'CREATING'
				}
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		), BotoResponse(
			method='get_access_preview',
			service_response={
				'accessPreview': {
					'id': access_preview_id,
					'analyzerArn': analyzer_arn,
					'createdAt': datetime(2015, 1, 1),
					'configurations': {},
					'status': 'CREATING'
				}
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)]

	def get_list_access_preview_findings_response(self, access_preview_id):
		return None


class MockBadRequest(MockValidationResult):
	def __init__(self, custom_validate_policy_type=None):
		expected_params_validate_policy = self.build_expected_validate_policy_params(custom_validate_policy_type)
		super(MockBadRequest, self).__init__(expected_params_validate_policy=expected_params_validate_policy)

	def get_create_access_preview_response(self, access_preview_id):
		return BotoClientError(
			method='create_access_preview',
			service_error_code='BadRequestException',
			service_message='[instance failed to match exactly one schema (matched 0 out of 12)]'
		)


class MockInvalidConfiguration(MockValidationResult):
	def __init__(self, code='SOME_CODE', finding_type='ERROR'):
		super(MockInvalidConfiguration, self).__init__()
		self.code = code
		self.finding_type = finding_type

	def get_validate_resource_policy_response(self):
		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': [{
					'issueCode': self.code,
					'findingDetails': 'details',
					'findingType': self.finding_type,
					'learnMoreLink': 'link',
					'locations': []
				}]
			}
		)

	def get_get_access_preview_response(self, access_preview_id):
		return BotoResponse(
			method='get_access_preview',
			service_response={
				'accessPreview': {
					'id': access_preview_id,
					'analyzerArn': analyzer_arn,
					'createdAt': datetime(2015, 1, 1),
					'configurations': {},
					'status': 'FAILED',
					'statusReason': {
						'code': 'INVALID_CONFIGURATION'
					}
				}
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)


def validate_identities(*mock_validation_results):
	responses = [use_existing_analyzer()]
	for result in mock_validation_results:
		validate_policy_response = result.get_validate_identity_policy_response()
		if validate_policy_response is not None:
			responses.append(validate_policy_response)

	return responses


def validate_resources(*mock_validation_results):
	access_preview_ids = [str(uuid.uuid4()) for _ in mock_validation_results]

	responses = [use_existing_analyzer()]
	for index, result in enumerate(mock_validation_results):
		validate_policy_response = result.get_validate_resource_policy_response()
		if validate_policy_response is not None:
			responses.append(validate_policy_response)

		create_access_preview_response = result.get_create_access_preview_response(access_preview_ids[index])
		if create_access_preview_response is not None:
			responses.append(create_access_preview_response)

	for index, result in enumerate(mock_validation_results):
		get_access_preview_response = result.get_get_access_preview_response(access_preview_ids[index])
		if get_access_preview_response is not None:
			if isinstance(get_access_preview_response, list):
				responses.extend(get_access_preview_response)
			else:
				responses.append(get_access_preview_response)

		list_access_preview_findings_response = result.get_list_access_preview_findings_response(access_preview_ids[index])
		if list_access_preview_findings_response is not None:
			responses.append(list_access_preview_findings_response)

	return responses


def validate_roles(*mock_validation_results):
	access_preview_ids = [str(uuid.uuid4()) for _ in mock_validation_results]

	responses = [use_existing_analyzer()]
	for index, result in enumerate(mock_validation_results):
		validate_resource_policy_response = result.get_validate_resource_policy_response()
		if validate_resource_policy_response is not None:
			responses.append(validate_resource_policy_response)

		create_access_preview_response = result.get_create_access_preview_response(access_preview_ids[index])
		if create_access_preview_response is not None:
			responses.append(create_access_preview_response)

		validate_identity_policy_response = result.get_validate_identity_policy_response()
		if validate_identity_policy_response is not None:
			responses.append(validate_identity_policy_response)

	for index, result in enumerate(mock_validation_results):
		get_access_preview_response = result.get_get_access_preview_response(access_preview_ids[index])
		if get_access_preview_response is not None:
			if isinstance(get_access_preview_response, list):
				responses.extend(get_access_preview_response)
			else:
				responses.append(get_access_preview_response)

		list_access_preview_findings_response = result.get_list_access_preview_findings_response(
			access_preview_ids[index])
		if list_access_preview_findings_response is not None:
			responses.append(list_access_preview_findings_response)

	return responses
