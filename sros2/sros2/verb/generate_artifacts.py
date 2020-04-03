# Copyright 2019 Open Source Robotics Foundation, Inc.
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

import os
import sys

try:
    from argcomplete.completers import DirectoriesCompleter
except ImportError:
    def DirectoriesCompleter():
        return None
try:
    from argcomplete.completers import FilesCompleter
except ImportError:
    def FilesCompleter(*, allowednames, directories):
        return None

from sros2.api import _key, _keystore, _permission, _policy
from sros2.policy import load_policy
from sros2.verb import VerbExtension


class GenerateArtifactsVerb(VerbExtension):
    """Generate keys and permission files from a list of identities and policy files."""

    def add_arguments(self, parser, cli_name):
        arg = parser.add_argument('-k', '--keystore-root-path', help='root path of keystore')
        arg.completer = DirectoriesCompleter()
        parser.add_argument(
            '-c', '--security-contexts', nargs='*', default=[],
            help='list of identities, aka ROS security contexts names')
        arg = parser.add_argument(
            '-p', '--policy-files', nargs='*', default=[],
            help='list of policy xml file paths')
        arg.completer = FilesCompleter(
            allowednames=('xml'), directories=False)

    def main(self, *, args):
        try:
            success = _generate_artifacts(
                args.keystore_root_path, args.security_contexts, args.policy_files)
        except FileNotFoundError as e:
            raise RuntimeError(str(e))
        return 0 if success else 1


def _generate_artifacts(keystore_path=None, identity_names=[], policy_files=[]):
    if keystore_path is None:
        keystore_path = _get_keystore_path_from_env()
        if keystore_path is None:
            return False
    if not _keystore.is_valid_keystore(keystore_path):
        print('%s is not a valid keystore, creating new keystore' % keystore_path)
        _keystore.create_keystore(keystore_path)

    # create keys for all provided identities
    for identity in identity_names:
        if not _key.create_key(keystore_path, identity):
            return False
    for policy_file in policy_files:
        policy_tree = load_policy(policy_file)
        contexts_element = policy_tree.find('contexts')
        for context in contexts_element:
            identity_name = context.get('path')
            if identity_name not in identity_names:
                if not _key.create_key(keystore_path, identity_name):
                    return False
            policy_element = _policy.get_policy_from_tree(identity_name, policy_tree)
            _permission.create_permissions_from_policy_element(
                keystore_path, identity_name, policy_element)
    return True


def _get_keystore_path_from_env():
    root_keystore_env_var = 'ROS_SECURITY_ROOT_DIRECTORY'
    root_keystore_path = os.getenv(root_keystore_env_var)
    if root_keystore_path is None:
        print('%s is empty' % root_keystore_env_var, file=sys.stderr)
    return root_keystore_path
