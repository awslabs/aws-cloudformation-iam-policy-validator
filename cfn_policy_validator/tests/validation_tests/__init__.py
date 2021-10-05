import uuid
from datetime import datetime

from cfn_policy_validator.tests.boto_mocks import mock_test_setup, BotoResponse

analyzer_arn = 'arn:aws:access-analyzer:us-east-1:111222333444:analyzer/MyAnalyzer'


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
	def __init__(self, expected_params_create_access_preview=None):
		self.expected_params_create_access_preview = expected_params_create_access_preview

	def get_validate_resource_policy_response(self):
		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': []
			}
		)

	def get_validate_identity_policy_response(self):
		return BotoResponse(
			method='validate_policy',
			service_response={
				'findings': []
			}
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


class MockAccessPreviewFinding(MockValidationResult):
	def get_list_access_preview_findings_response(self, access_preview_id):
		return BotoResponse(
			method='list_access_preview_findings',
			service_response={
				'findings':  [{
					'createdAt': datetime(2015, 1, 1),
					'id': str(uuid.uuid4()),
					'resourceOwnerAccount': '1111222233334444',
					'resourceType': 'AWS::IAM::Role',  # type is ignored, but is required
					'status': 'ACTIVE',
					'changeType': 'NEW'
				}]
			},
			expected_params={
				'accessPreviewId': access_preview_id,
				'analyzerArn': analyzer_arn
			}
		)


class MockValidateResourcePolicyFinding(MockValidationResult):
	def __init__(self, code, finding_type='ERROR'):
		super(MockValidateResourcePolicyFinding, self).__init__()
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


class MockValidateIdentityPolicyFinding(MockValidationResult):
	def __init__(self, code, finding_type='ERROR'):
		super(MockValidateIdentityPolicyFinding, self).__init__()
		self.code = code
		self.finding_type = finding_type

	def get_validate_identity_policy_response(self):
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


class MockValidateIdentityAndResourcePolicyFinding(MockValidationResult):
	def __init__(self, resource_code, resource_finding_type, identity_code, identity_finding_type):
		super(MockValidateIdentityAndResourcePolicyFinding, self).__init__()
		self.mock_validate_resource_policy_finding = MockValidateResourcePolicyFinding(resource_code, resource_finding_type)
		self.mock_validate_identity_policy_finding = MockValidateIdentityPolicyFinding(identity_code, identity_finding_type)

	def get_validate_identity_policy_response(self):
		return self.mock_validate_identity_policy_finding.get_validate_identity_policy_response()

	def get_validate_resource_policy_response(self):
		return self.mock_validate_resource_policy_finding.get_validate_resource_policy_response()


class MockNoFindings(MockValidationResult):
	def __init__(self, expected_params_create_access_preview=None):
		super(MockNoFindings, self).__init__(expected_params_create_access_preview)


class MockUnknownError(MockValidationResult):
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
