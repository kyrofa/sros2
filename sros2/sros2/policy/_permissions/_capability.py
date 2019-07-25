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
import contextlib

from lxml import etree

from ... import PolicyError


class UnsupportedQualifierError(PolicyError):

    def __init__(self, qualifier_string: str):
        super().__init__('Unsupported qualifier: {!r}'.format(qualifier_string))
        self.qualifier = qualifier_string


@enum.unique
class CapabilityType(enum.Enum):
    # Enum values should map to their XML values
    SUBSCRIBE = 'subscribe'
    PUBLISH = 'publish'
    REPLY = 'reply'
    REQUEST = 'request'
    CALL = 'call'
    EXECUTE = 'execute'


@enum.unique
class CapabilityQualifier(enum.Enum):
    # Enum values should map to their XML values
    ALLOW = 'ALLOW'
    DENY = 'DENY'


class Capability:
    """A capability is covered by a given permission (i.e. permission to have the capability)."""

    @classmethod
    def from_fields(
            cls, capability_type: CapabilityType, qualifier: CapabilityQualifier) -> 'Capability':
        # This isn't a valid permission type, but this class needs an XML backing store. Create
        # one to serve until this is attached to a policy.
        permission = etree.Element('permissions')
        capability = cls(permission, capability_type)
        capability.set_qualifier(qualifier)
        return capability

    def __init__(self, permission: etree.Element, capability_type: CapabilityType) -> None:
        self._capability_type = capability_type
        self._use_permission(permission)

    def _use_permission(self, permission: etree.Element) -> None:
        with contextlib.suppress(UnsupportedQualifierError):
            qualifier = self.get_qualifier()
        self._permission = permission

        if qualifier:
            self.set_qualifier(qualifier)

    def get_type(self) -> str:
        """
        Return the type of the permission.

        :rtype: PermissionType
        """
        return self._capability_type

    def get_qualifier(self) -> CapabilityQualifier:
        """
        Return the type of the rule.

        :rtype: PermissionRuleType
        """
        qualifier_string = self._permission.get(self._capability_type.value)
        try:
            return CapabilityQualifier(qualifier_string)
        except ValueError as e:
            raise UnsupportedQualifierError(qualifier_string) from e

    def set_qualifier(self, qualifier: CapabilityQualifier) -> None:
        self._permission[self._capability_type.value] = qualifier.value
