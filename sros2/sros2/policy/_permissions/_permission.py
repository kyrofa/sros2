# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
from typing import List

from lxml import etree

from . import PolicyError
from ._expression import Expression


class UnsupportedPolicyError(PolicyError):
    """Not necessarily an invalid policy, but one this class doesn't support."""

    def __init__(self, why):
        super().__init__('Unsupported SROS 2 policy: {}'.format(why))


class UnsupportedPermissionTypeError(PolicyError):

    def __init__(self, type_string: str):
        super().__init__('Unsupported permission type: {!r}'.format(type_string))
        self.type = type_string


@enum.unique
class PermissionType(enum.Enum):
    # Enum values should map to their XML values
    TOPIC = 'topics'
    SERVICE = 'services'
    ACTION = 'actions'


@enum.unique
class PermissionQualifier(enum.Enum):
    # Enum values should map to their XML values
    ALLOW = 'ALLOW'
    DENY = 'DENY'


class Permission:
    """Class representation of a profile's permission within an XML security policy."""

    def __init__(self, permission: etree.Element) -> None:
        """
        Create new Permission instance.

        :param etree.Element profile: XML Element containing the permission.
        """
        self._permission = permission

    def get_type(self) -> PermissionType:
        """
        Return the type of the permission.

        :rtype: PermissionType
        """
        try:
            return PermissionType(self._permission.tag)
        except ValueError as e:
            raise UnsupportedPermissionTypeError(self._permission.tag) from e

    def get_rule_type(self) -> PermissionRuleType:
        """
        Return the type of the rule.

        :rtype: PermissionRuleType
        """
        keys = self._permission.keys()
        if len(keys) != 1:
            raise UnsupportedPolicyError(
                'Expected a single attribute to determine rule type, got {!r}'.format(keys))

        return PermissionRuleType(keys[0])

    def get_rule_qualifier(self) -> PermissionRuleQualifier:
        """
        Return the qualifier of the rule.

        :rtype: PermissionRuleQualifier
        """
        return PermissionRuleQualifier(self._permission.get(self.get_rule_type().value))

    def get_expressions(self) -> List[Expression]:
        """
        Return all expressions making up the permission.

        :rtype: list
        """
        expressions = []
        for child in self._permission:
            expressions.append(Expression(child))

        return expressions

    def add_expression(self, expression: Expression) -> Expression:
        """
        Add expression to the permission.

        :param Expression expression: Expression to be added.

        :returns: The expression that was added
        :rtype: Expression

        Future modifications of the expression will be reflected in this permission once this
        function is called.
        """
        self._permission.append(expression._expression)
        return expression
