"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.node_evaluator import NodeEvaluator
from cfn_policy_validator.tests.utils import load, account_config, load_resources


class WhenEvaluatingAPropertyWithAnUnsupportedFunction(unittest.TestCase):
    def test_raises_an_error(self):
        template = load_resources({
            'ResourceA': {
                'Type': 'AWS::Random::Service',
                'Properties': {
                    'PropertyA': {
                        "Fn::GetAZs": "us-east-1"
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        # assert that unsupported functions are just passed as is.  This will fail in IAM AA, but still allows the user
        # to ignore an individual policy finding
        self.assertEqual({'Fn::GetAZs': 'us-east-1'}, result)


# this is not a valid CloudFormation template, but this test is just to ensure that we can handle situations like these
class WhenEvaluatingInvalidTemplateWithRefCycle(unittest.TestCase):
    def test_does_not_overflow(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceB'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'RoleName': {
                            'Ref': 'ResourceA'
                        }
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})

        result = node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        # The cycle is ignored because we eventually fallback to just taking the resource name
        self.assertEqual('ResourceA', result)


class WhenEvaluatingInvalidTemplateWithGetAttCycle(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceB', 'PropertyA']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'PropertyA']
                        }
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)

        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual('Cycle detected for ResourceB and PropertyA.', str(cm.exception))


class WhenEvaluatingInvalidTemplateWithMultipleGetAttCycles(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceB', 'PropertyA']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceC', 'PropertyA']
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'PropertyA']
                        }
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual('Cycle detected for ResourceB and PropertyA.', str(cm.exception))


class WhenEvaluatingInvalidTemplateWithSubCycle(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Sub': 'This is a line of text with value ${ResourceB.PropertyB}'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyB': {
                            'Fn::Sub': 'This is a line of text with value ${ResourceC.PropertyC}'
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyC': {
                            'Fn::Sub': 'This is a line of text with value ${ResourceA.PropertyA}'
                        }
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual('Cycle detected for ResourceB and PropertyB.', str(cm.exception))


class WhenEvaluatingInvalidTemplateWithCycleDuringArnGeneration(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceB', 'Arn']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'Path': {'Ref': 'ResourceA'},
                        'RoleName': {'Fn::GetAtt': ['ResourceA', 'PropertyA']}
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertEqual('Cycle detected for ResourceB and RoleName.', str(cm.exception))


class WhenEvaluatingInvalidTemplateWithCycleDuringSqsCustomRefEval(unittest.TestCase):
    def test_raises_an_error(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::SQS::Queue',
                    'Properties': {
                        'QueueName': {
                            'Fn::GetAtt': ['ResourceC', 'PropertyA']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::SQS::QueuePolicy',
                    'Properties': {
                        'Queues': [
                            {'Ref': 'ResourceA'}
                        ]
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceD', 'PropertyA']
                        }
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceC', 'PropertyA']
                        }
                    }
                }
            }
        })

        parameters = {
            'Param1': 'Param1Value'
        }

        node_evaluator = NodeEvaluator(template, account_config, parameters)
        with self.assertRaises(ApplicationError) as cm:
            node_evaluator.eval(template['Resources']['ResourceB']['Properties']['Queues'])

        self.assertEqual('Cycle detected for ResourceC and PropertyA.', str(cm.exception))


class WhenEvaluatingValidTemplateAndObjectHasTheSameChildReference(unittest.TestCase):
    def test_does_not_detect_as_cycle(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'SubPropertyA': {'Ref': 'ResourceB'},
                            'SubPropertyB': {'Ref': 'ResourceB'}
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'RoleName': 'MyRole'
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})
        node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertTrue(True, 'No exception raised.')


class WhenEvaluatingValidTemplateAndListHasTheSameChildReference(unittest.TestCase):
    def test_does_not_detect_as_cycle(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'SubPropertyA': [
                                {'Ref': 'ResourceB'},
                                {'Ref': 'ResourceB'}
                            ]
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'RoleName': 'MyRole'
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})
        node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])
        self.assertTrue(True, 'No exception raised.')


class WhenEvaluatingValidTemplateAndPropertyHasTheSameChildReference(unittest.TestCase):
    def test_does_not_detect_as_cycle(self):
        template = load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'PropertyA': {
                            'SubPropertyA': [
                                {'Ref': 'ResourceB'},
                                {'Ref': 'ResourceB'}
                            ],
                            'SubPropertyB': {'Ref': 'ResourceB'}
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'RoleName': 'MyRole'
                    }
                }
            }
        })

        node_evaluator = NodeEvaluator(template, account_config, {})
        node_evaluator.eval(template['Resources']['ResourceA']['Properties']['PropertyA'])

        self.assertTrue(True, 'No exception raised.')
