"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

from cfn_policy_validator import client

# only look up the user id if it's requested
canonical_user_id = None


# Resolution of the canonical user in an account which is a possible principal value for a policy and also
# used when evaluating S3 bucket ACLs.
def get_canonical_user(region):
    global canonical_user_id
    if canonical_user_id is not None:
        return canonical_user_id

    s3_client = client.build('s3', region)
    response = s3_client.list_buckets()
    canonical_user_id = response['Owner']['ID']
    return canonical_user_id
