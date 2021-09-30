# used to map common CFN resource types to their name properties to more accurately generate names for common resources
# instead of defaulting to the CFN resource's logical name
name_hints = {
	'AWS::S3::Bucket': 'BucketName',
	'AWS::Lambda::Function': 'FunctionName',
	'AWS::IAM::Role': 'RoleName',
	'AWS::IAM::User': 'UserName',
	'AWS::IAM::Group': 'GroupName',
	'AWS::SQS::Queue': 'QueueName'
}
