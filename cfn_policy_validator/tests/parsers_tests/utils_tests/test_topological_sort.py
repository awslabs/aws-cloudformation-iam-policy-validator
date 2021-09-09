"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import unittest

from cfn_policy_validator.application_error import ApplicationError
from cfn_policy_validator.parsers.utils.topological_sorter import TopologicalSorter
from cfn_policy_validator.tests.utils import load, expected_type_error


def get_index_of(sorted_resources, name):
    for index, item in enumerate(sorted_resources):
        if item.logical_name == name:
            return index

    raise Exception(f'{name} not found in sorted resources')


class WhenSortingWithReferenceDependencies(unittest.TestCase):
    def test_resources_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceD'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceA'
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceD'
                        }
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': 'StaticProperty'
                    }
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, d_index, "A does not appear after D")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(c_index, d_index, "C does not appear after D")


class WhenSortingWithGetAttDependencies(unittest.TestCase):
    def test_resources_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceC', 'Arn']
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'OtherAttr']
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': 'StaticProperty'
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'OtherAttr']
                        },
                        'PropertyB': {
                            'Fn::GetAtt': ['ResourceB', 'Arn']
                        }
                    }
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, c_index, "A does not appear after C")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(d_index, a_index, "D does not appear after A")
        self.assertGreater(d_index, b_index, "D does not appear after B")

    def test_schema_is_validated(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'Path': {'Ref': 'ResourceA'},
                        'RoleName': {'Fn::GetAtt': 'ResourceA'}
                    }
                }
            }
        }))

        with self.assertRaises(ApplicationError) as cm:
            sorter.sort_resources()

        self.assertEqual(expected_type_error('Fn::GetAtt', 'array', "'ResourceA'"), str(cm.exception))


class WhenSortingWithSubDependencies(unittest.TestCase):
    def test_resources_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Sub': '${ResourceC.Arn}'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'Property']
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': 'StaticProperty'
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'OtherAttr']
                        },
                        'PropertyB': {
                            'Fn::GetAtt': ['ResourceB', 'Arn']
                        }
                    }
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, c_index, "A does not appear after C")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(d_index, a_index, "D does not appear after A")
        self.assertGreater(d_index, b_index, "D does not appear after B")

    def test_dependencies_with_long_form_sub_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::Sub': ["www.${MyProperty}", {"MyProperty": {"Fn::GetAtt": ["ResourceC", "Arn"]}}]
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'Arn']
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': 'StaticProperty'
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Fn::GetAtt': ['ResourceA', 'OtherAttr']
                        },
                        'PropertyB': {
                            'Fn::GetAtt': ['ResourceB', 'Arn']
                        }
                    }
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, c_index, "A does not appear after C")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(d_index, a_index, "D does not appear after A")
        self.assertGreater(d_index, b_index, "D does not appear after B")

    def test_schema_is_validated(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::IAM::Role',
                    'Properties': {
                        'Path': {'Ref': 'ResourceA'},
                        'RoleName': {'Fn::Sub': {'ResourceA': 'Blah'}}
                    }
                }
            }
        }))

        with self.assertRaises(ApplicationError) as cm:
            sorter.sort_resources()

        self.assertEqual(expected_type_error('Fn::Sub', 'array or string', "{'ResourceA': 'Blah'}"), str(cm.exception))


class WhenSortingWithExplicitDependsOn(unittest.TestCase):
    def test_resources_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {},
                    'DependsOn': ['ResourceC', 'ResourceD']
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {},
                    'DependsOn': 'ResourceA'
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {}
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {},
                    'DependsOn': 'ResourceC'
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, c_index, "A does not appear after C")
        self.assertGreater(a_index, d_index, "A does not appear after D")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(d_index, c_index, "D does not appear after B")


class WhenSortingWithRefDependenciesThatHaveCycle(unittest.TestCase):
    def test_resources_are_sorted_in_dependency_order(self):
        sorter = TopologicalSorter(load({
            'Resources': {
                'ResourceA': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceD'
                        }
                    }
                },
                'ResourceB': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceA'
                        }
                    }
                },
                'ResourceC': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'PropertyA': {
                            'Ref': 'ResourceD'
                        }
                    }
                },
                'ResourceD': {
                    'Type': 'AWS::Random::Service',
                    'Properties': {
                        'Ref': 'ResourceA'
                    }
                }
            }
        }))

        sorted_resources = sorter.sort_resources()

        a_index = get_index_of(sorted_resources, 'ResourceA')
        b_index = get_index_of(sorted_resources, 'ResourceB')
        c_index = get_index_of(sorted_resources, 'ResourceC')
        d_index = get_index_of(sorted_resources, 'ResourceD')

        self.assertGreater(a_index, d_index, "A does not appear after D")
        self.assertGreater(b_index, a_index, "B does not appear after A")
        self.assertGreater(c_index, d_index, "C does not appear after D")
