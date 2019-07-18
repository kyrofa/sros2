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
from typing import Dict, List, Tuple

from lxml import etree

from ._permission import Permission, PermissionType, PermissionQualifier


@enum.unique
class TopicsCapability(enum.Enum):
    # Enum values should map to their XML values
    SUBSCRIBE = 'subscribe'
    PUBLISH = 'publish'


class TopicsPermission(Permission):
    """Class representation of a profile's permission within an XML security policy."""

    @classmethod
    def from_fields(
            cls,
            capabilities: Dict[TopicsCapability: PermissionQualifier]) -> 'TopicsPermission':
        """
        Create new Permission instance from its fields.

        :param PermissionType permission_type: The type of permission.
        :param PermissionRuleType rule_type: The type of rule.
        :param PermissionRuleQualifier rule_qualifier: Qualifier for the rule.

        :returns: The newly-created permission.
        :rtype: Permission
        """
        permission = etree.Element(PermissionType.TOPIC.value)

        for capability, qualifier in capabilities.items():
            permission.attrib[capability.value] = qualifier.value

        return cls(permission)

    # def get_type(self) -> PermissionType:
    #     """
    #     Return the type of the permission.

    #     :rtype: PermissionType
    #     """
    #     return PermissionType(self._permission.tag)

    # def get_rule_type(self) -> PermissionRuleType:
    #     """
    #     Return the type of the rule.

    #     :rtype: PermissionRuleType
    #     """
    #     keys = self._permission.keys()
    #     if len(keys) != 1:
    #         raise UnsupportedPolicyError(
    #             'Expected a single attribute to determine rule type, got {!r}'.format(keys))

    #     return PermissionRuleType(keys[0])

    # def get_rule_qualifier(self) -> PermissionRuleQualifier:
    #     """
    #     Return the qualifier of the rule.

    #     :rtype: PermissionRuleQualifier
    #     """
    #     return PermissionRuleQualifier(self._permission.get(self.get_rule_type().value))

    # def get_expressions(self) -> List[Expression]:
    #     """
    #     Return all expressions making up the permission.

    #     :rtype: list
    #     """
    #     expressions = []
    #     for child in self._permission:
    #         expressions.append(Expression(child))

    #     return expressions

    # def add_expression(self, expression: Expression) -> Expression:
    #     """
    #     Add expression to the permission.

    #     :param Expression expression: Expression to be added.

    #     :returns: The expression that was added
    #     :rtype: Expression

    #     Future modifications of the expression will be reflected in this permission once this
    #     function is called.
    #     """
    #     self._permission.append(expression._expression)
    #     return expression
