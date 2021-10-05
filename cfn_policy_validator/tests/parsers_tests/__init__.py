from cfn_policy_validator.tests.boto_mocks import mock_test_setup


def mock_node_evaluator_setup(**kwargs):
	"""
	Mock calls made by node evaluator.  Used even in tests that don't make explicit calls to AWS services since building
	boto3 clients can be a perf hit when running tests.
	"""

	if 'ssm' not in kwargs:
		kwargs['ssm'] = []

	if 'cloudformation' not in kwargs:
		kwargs['cloudformation'] = []

	return mock_test_setup(
		**kwargs
	)


def mock_identity_parser_setup(**kwargs):
	if 'iam' not in kwargs:
		kwargs['iam'] = []

	return mock_node_evaluator_setup(
		**kwargs
	)
