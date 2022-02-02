"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import datetime
import json


class Output:
    """
    Parser output representation.  Populated by identity and resource parsers.
    """

    def __init__(self, account_config):
        self.Region = account_config.region
        self.Account = account_config.account_id
        self.Partition = account_config.partition
        self.Roles = []
        self.PermissionSets = []
        self.Users = []
        self.Groups = []
        self.Resources = []
        self.OrphanedPolicies = []

    def print(self):
        as_json_string = json.dumps(self, default=self.default_to_json, indent=4)
        print(as_json_string)

    def to_json(self):
        return json.loads(
            json.dumps(self, default=self.default_to_json, indent=4)
        )

    @classmethod
    def default_to_json(cls, value):
        if isinstance(value, datetime.date):
            return value.isoformat()

        # allow a class to specify custom JSON serialization
        custom_to_json = getattr(value, "custom_to_json", None)
        if custom_to_json is None:
            return value.__dict__
        else:
            return custom_to_json()

    def __eq__(self, other):
        if not isinstance(other, Output):
            return False

        # written this way to allow for debugging
        permission_sets_are_equal = sorted(self.PermissionSets) == sorted(other.PermissionSets)
        roles_are_equal = sorted(self.Roles) == sorted(other.Roles)
        users_are_equal = sorted(self.Users) == sorted(other.Users)
        groups_are_equal = sorted(self.Groups) == sorted(other.Groups)
        resources_are_equal = sorted(self.Resources) == sorted(other.Resources)
        policies_are_equal = sorted(self.OrphanedPolicies) == sorted(other.OrphanedPolicies)
        return roles_are_equal and users_are_equal and groups_are_equal and \
               resources_are_equal and policies_are_equal and permission_sets_are_equal

    def __hash__(self):
        return hash((self.Roles, self.Users, self.Groups, self.Resources, self.OrphanedPolicies))


class IdentityWithPolicies:
    def __init__(self):
        self.Policies = []

    def add_policy(self, policy):
        self.Policies.append(policy)

    def __eq__(self, other):
        if not isinstance(other, IdentityWithPolicies):
            return False

        return self.Policies == other.Policies

    def __hash__(self):
        return hash(self.Policies)


class User(IdentityWithPolicies):
    def __init__(self, user_name, user_path):
        self.UserName = user_name
        self.UserPath = user_path
        super(User, self).__init__()

    def __eq__(self, other):
        if not isinstance(other, User):
            return False

        return self.UserName == other.UserName and\
            self.UserPath == other.UserPath and\
            super().__eq__(other)

    def __lt__(self, other):
        return self.UserName < other.UserName

    def __hash__(self):
        return hash((self.UserName, self.UserPath, super().__hash__()))


class Group(IdentityWithPolicies):
    def __init__(self, group_name, group_path):
        self.GroupName = group_name
        self.GroupPath = group_path
        super(Group, self).__init__()

    def __eq__(self, other):
        if not isinstance(other, Group):
            return False

        return self.GroupName == other.GroupName and\
            self.GroupPath == other.GroupPath and\
            super().__eq__(other)

    def __lt__(self, other):
        return self.GroupName < other.GroupName

    def __hash__(self):
        return hash((self.GroupName, self.GroupPath, super().__hash__()))


class Role(IdentityWithPolicies):
    def __init__(self, role_name, role_path, trust_policy):
        self.RoleName = role_name
        self.RolePath = role_path
        self.TrustPolicy = trust_policy
        super(Role, self).__init__()

    def __eq__(self, other):
        if not isinstance(other, Role):
            return False

        return self.RoleName == other.RoleName and\
            self.RolePath == other.RolePath and\
            super().__eq__(other)

    def __lt__(self, other):
        return self.RoleName < other.RoleName

    def __hash__(self):
        return hash((self.RoleName, self.RolePath, super().__hash__()))


class PermissionSet(IdentityWithPolicies):
    def __init__(self, name):
        self.Name = name
        super(PermissionSet, self).__init__()

    def __eq__(self, other):
        if not isinstance(other, PermissionSet):
            return False

        return self.Name == other.Name and\
            super().__eq__(other)

    def __lt__(self, other):
        return self.Name < other.Name

    def __hash__(self):
        return hash((self.Name, super().__hash__()))


class Policy:
    def __init__(self, name, document, path="/"):
        self.Name = name
        self.Policy = document
        self.Path = path

    def __eq__(self, other):
        if not isinstance(other, Policy):
            return False

        names_are_equal = self.Name == other.Name
        paths_are_equal = self.Path == other.Path
        policies_are_equal = self.Policy == other.Policy

        return names_are_equal and paths_are_equal and policies_are_equal

    def __lt__(self, other):
        return self.Name < other.Name

    def __hash__(self):
        return hash((self.Name, self.Path))


class Resource:
    def __init__(self, resource_name, resource_type, policy, configuration=None):
        if configuration is None:
            configuration = {}

        self.ResourceName = resource_name
        self.ResourceType = resource_type
        self.Policy = policy
        self.Configuration = configuration

    def __eq__(self, other):
        if not isinstance(other, Resource):
            return False

        names_are_equal = self.ResourceName == other.ResourceName
        types_are_equal = self.ResourceType == other.ResourceType
        policies_are_equal = self.Policy == other.Policy
        configuration_is_equal = self.Configuration == other.Configuration

        return names_are_equal and types_are_equal and policies_are_equal and configuration_is_equal

    def custom_to_json(self):
        self_as_dict = self.__dict__
        if len(self_as_dict['Configuration']) == 0:
            self_as_dict.pop('Configuration')

        return self_as_dict

    def __lt__(self, other):
        return self.ResourceName < other.ResourceName

    def __hash__(self):
        return hash((self.ResourceName, self.ResourceType, self.Policy))
