"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging
import sys

LOGGER = logging.getLogger('cfn-policy-validator')


def configure_logging(enable_logging):
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    LOGGER.setLevel(logging.INFO)

    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(log_formatter)

    for handler in LOGGER.handlers:
        LOGGER.removeHandler(handler)
    LOGGER.addHandler(console_handler)

    if not enable_logging:
        LOGGER.disabled = True
