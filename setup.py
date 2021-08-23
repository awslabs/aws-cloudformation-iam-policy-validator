"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import codecs
import setuptools
import re


def get_version(filename):
    with codecs.open(filename, 'r', 'utf-8') as fp:
        contents = fp.read()
    return re.search(r"__version__ = ['\"]([^'\"]+)['\"]", contents).group(1)


version = get_version('cfn_policy_validator/version.py')

setuptools.setup(
    name="cfn-policy-validator",
    version=version,
    author="Matt Luttrell",
    author_email="matluttr@amazon.com",
    description="Parses IAM identity-based and resource-based policies from a CloudFormation template and runs them through IAM Access Analyzer checks.",
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(exclude=["*.tests", "*_tests"]),
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ],
    entry_points={"console_scripts": "cfn-policy-validator=cfn_policy_validator.main:main"},
    python_requires='>=3.6',
    package_data={
        '': ['*.json']
    },
    install_requires=[
        'boto3>=1.17',
        'pyYAML>=5.3',
        'urllib3>=1.25',
        'jsonschema>=3.2'
    ]
)
