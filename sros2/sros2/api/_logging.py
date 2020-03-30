# Copyright 2020 Canonical Ltd
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
import pathlib
import sys

import lxml

import sros2.api


_LOGGING_VERSION = 1
_SECURITY_LOG_TAG = 'security_log'
_VERBOSITY_TAG = 'verbosity'
_DISTRIBUTE_TAG = 'distribute'
_FILE_TAG = 'file'
_QOS_TAG = 'qos'
_PROFILE_TAG = 'profile'
_RELIABILITY_TAG = 'reliability'
_HISTORY_TAG = 'history'
_DURABILITY_TAG = 'durability'
_LIVELINESS_TAG = 'liveliness'
_DEPTH_TAG = 'depth'
_DEADLINE_TAG = 'deadline'
_LIFESPAN_TAG = 'lifespan'
_LIVELINESS_LEASE_DURATION_TAG = 'liveliness_lease_duration'


@enum.unique
class Verbosity(enum.Enum):
    EMERGENCY = enum.auto()
    ALERT = enum.auto()
    CRITICAL = enum.auto()
    ERROR = enum.auto()
    WARNING = enum.auto()
    NOTICE = enum.auto()
    INFORMATIONAL = enum.auto()
    DEBUG = enum.auto()


def enable_logging(
        keystore_root: str, verbosity: Verbosity, *, identity: str = '', log_file: str = '',
        distribute=False) -> bool:
    if not sros2.api.is_valid_keystore(keystore_root):
        print(f"'{keystore_root!s}' is not a valid keystore", file=sys.stderr)
        return False

    if identity:
        _enable_logging_for_identity(
            keystore_root, identity, verbosity, log_file=log_file, distribute=distribute)
    else:
        for this_identity in pathlib.Path(keystore_root).iterdir():
            if this_identity.is_dir():
                _enable_logging_for_identity(
                    keystore_root, this_identity.name, verbosity, log_file=log_file,
                    distribute=distribute)

    return True


def _enable_logging_for_identity(
        keystore_root: str, identity: str, verbosity: Verbosity, *, log_file: str = '',
        distribute=False) -> None:
    security_log_element = lxml.etree.Element(_SECURITY_LOG_TAG)
    security_log_element.set('version', str(_LOGGING_VERSION))

    if log_file:
        log_file_element = lxml.etree.SubElement(security_log_element, _FILE_TAG)
        log_file_element.text = log_file
    else:
        security_log_element.append(
            lxml.etree.Comment(' Uncomment the following to log to file '))
        security_log_element.append(
            lxml.etree.Comment(f' <{_FILE_TAG}>/path/to/file.log</{_FILE_TAG}> '))

    verbosity_element = lxml.etree.SubElement(security_log_element, _VERBOSITY_TAG)
    verbosity_element.text = str(verbosity)

    distribute_element = lxml.etree.SubElement(security_log_element, _DISTRIBUTE_TAG)
    distribute_element.text = str(distribute).lower()

    # This utility does not currently support directly setting QoS, but add a nice
    # commented-out section outlining how to set it manually if desired.
    security_log_element.append(lxml.etree.Comment(
        ' The following applies when logging over DDS (i.e. distribute = true) '))
    qos_element = lxml.etree.SubElement(security_log_element, _QOS_TAG)
    qos_element.append(lxml.etree.Comment(f' <{_PROFILE_TAG}>DEFAULT</{_PROFILE_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_RELIABILITY_TAG}>RELIABLE</{_RELIABILITY_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_HISTORY_TAG}>KEEP_LAST</{_HISTORY_TAG}> '))
    qos_element.append(lxml.etree.Comment(
        f' <{_DURABILITY_TAG}>VOLATILE</{_DURABILITY_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_LIVELINESS_TAG}>AUTOMATIC</{_LIVELINESS_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_DEPTH_TAG}>10</{_DEPTH_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_DEADLINE_TAG}>10.5</{_DEADLINE_TAG}> '))
    qos_element.append(lxml.etree.Comment(f' <{_LIFESPAN_TAG}>12.2</{_LIFESPAN_TAG}> '))
    qos_element.append(lxml.etree.Comment(
        f' <{_LIVELINESS_LEASE_DURATION_TAG}>30.4</{_LIVELINESS_LEASE_DURATION_TAG}> '))

    path = pathlib.Path(keystore_root).joinpath(identity.lstrip('/'))
    logging_path = path.joinpath('logging.xml')

    with open(logging_path, 'wb') as f:
        f.write(lxml.etree.tostring(
            security_log_element, xml_declaration=True, encoding='UTF-8', pretty_print=True))
