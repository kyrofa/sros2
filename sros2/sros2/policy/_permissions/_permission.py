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
from typing import Dict, Iterable, Set

from lxml import etree

from .. import PolicyError, _expression, _profile
from ._capabilities import _capability


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


class UnsupportedPolicyError(PolicyError):
    """Not necessarily an invalid policy, but one this class doesn't support."""

    def __init__(self, why):
        super().__init__('Unsupported SROS 2 policy: {}'.format(why))


class UnsupportedPermissionTypeError(PolicyError):

    def __init__(self, type_string: str):
        super().__init__('Unsupported permission type: {!r}'.format(type_string))
        self.type = type_string


class UnsupportedCapabilityTypeError(PolicyError):

    def __init__(self, permission_type: PermissionType, capability_type: _capability.CapabilityType):
        super().__init__('Permission type {!r} does not support capability type {!r}'.format(
            permission_type.value, capability_type.value))
        self.permission_type = permission_type
        self.capability_type = capability_type


class Permission:
    """Class representation of a profile's permission within an XML security policy."""

    _supported_capabilities = set()  # type: Set[_capability.Capability]
    _type = None  # type: PermissionType
    _expression_type = None  # type: _expression.ExpressionType

    @classmethod
    def from_fields(
            cls,
            capabilities: Dict[_capability.Capability: PermissionQualifier]) -> 'Permission':
        """
        Create new Permission instance from its fields.

        :param PermissionType permission_type: The type of permission.
        :param PermissionRuleType rule_type: The type of rule.
        :param PermissionRuleQualifier rule_qualifier: Qualifier for the rule.

        :returns: The newly-created permission.
        :rtype: Permission
        """
        permission = etree.Element(cls._type.value)

        for capability, qualifier in capabilities.items():
            permission.attrib[capability.value] = qualifier.value

        return cls(permission)

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

    def get_capabilities(self) -> Iterable[_capability.Capability]:
        capabilities = []
        for attribute in self._permission.keys():
            capabilities.append(_capability.Capability(self._permission, attribute))

        return capabilities

    def add_capability(self, capability: _capability.Capability) -> _capability.Capability:
        if capability.get_type() not in self._supported_capabilities:
            raise UnsupportedCapabilityTypeError(self.get_type(), capability)

        capability._use_permission(self)
        return capability

    def get_expressions(self) -> Iterable[str]:
        """
        Return all expressions making up the permission.

        :rtype: list
        """
        expressions = []
        for child in self._permission:
            expressions.append(child.text)

        return expressions

    def add_expression(self, pattern: str) -> _expression.Expression:
        profile = _profile.Profile(self._permission.parent())
        expression = _expression.Expression.from_fields(
            profile.get_fqn(), profile.get_namespace(), self._expression_type, pattern)
        self._permission.append(expression._expression)
        return expression
