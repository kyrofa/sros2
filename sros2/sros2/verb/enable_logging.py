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

try:
    from argcomplete.completers import DirectoriesCompleter
except ImportError:
    def DirectoriesCompleter():
        return None

from sros2.api import _logging
from sros2.verb import VerbExtension


class EnableLoggingVerb(VerbExtension):
    """Enable logging either for a particular participant or for the entire keystore."""

    def add_arguments(self, parser, cli_name):
        arg = parser.add_argument('ROOT', help='root path of keystore')
        arg.completer = DirectoriesCompleter()

        parser.add_argument('NAME', nargs='?', help='key name, aka ROS node name.')
        parser.add_argument(
            '--verbosity', help='log verbosity', choices=_logging.Verbosity.__members__,
            default=_logging.Verbosity.ERROR.name)
        parser.add_argument('--log-file', help='enable logging to file')
        parser.add_argument(
            '--distribute', action='store_true', help='enable distributing logging to DDS topic')

    def main(self, *, parser, args):
        if not (args.log_file or args.distribute):
            parser.error('at least one of --log-file or --distribute is required')

        success = _logging.enable_logging(
            args.ROOT, identity=args.NAME, verbosity=args.verbosity, log_file=args.log_file,
            distribute=args.distribute)

        return 0 if success else 1
