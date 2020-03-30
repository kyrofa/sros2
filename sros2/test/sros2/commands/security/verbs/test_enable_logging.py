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

import pathlib

import lxml

import pytest

from ros2cli import cli

from sros2.api import _logging, create_keystore


@pytest.fixture()
def keystore_dir(tmpdir_factory):
    keystore_dir = str(tmpdir_factory.mktemp('keystore'))

    # First, create the keystore
    assert create_keystore(keystore_dir)

    # Now using that keystore, create a keypair along with other files required by DDS
    # for a few different identities.
    assert cli.main(argv=['security', 'create_key', keystore_dir, '/test1']) == 0
    assert cli.main(argv=['security', 'create_key', keystore_dir, '/test2']) == 0

    return keystore_dir


def test_create_key_lacks_logging_config(keystore_dir):
    assert not pathlib.Path(f'{keystore_dir}/test1/logging.xml').exists()
    assert not pathlib.Path(f'{keystore_dir}/test2/logging.xml').exists()


@pytest.mark.parametrize('distribute', [True, False])
@pytest.mark.parametrize('log_file', [None, '/foo/bar'])
def test_enable_logging_single_identity(distribute, log_file, keystore_dir, capsys):
    argv = ['security', 'enable_logging', keystore_dir, '/test1']

    expected_elements = 3
    if distribute:
        argv.append('--distribute')

    if log_file:
        argv.append('--log-file')
        argv.append(log_file)
        expected_elements += 1

    if distribute or log_file:
        assert cli.main(argv=argv) == 0
    else:
        with pytest.raises(SystemExit) as e:
            cli.main(argv=argv)
        assert e.value.code != 0
        stderr = capsys.readouterr().err.strip()
        assert 'at least one of --log-file or --distribute is required' in stderr
        return

    logging_config_path = pathlib.Path(f'{keystore_dir}/test1/logging.xml')
    assert logging_config_path.exists()
    assert not pathlib.Path(f'{keystore_dir}/test2/logging.xml').exists()

    security_log_element = lxml.etree.parse(
        str(logging_config_path), lxml.etree.XMLParser(remove_comments=True)).getroot()
    assert security_log_element.tag == _logging._SECURITY_LOG_TAG
    assert len(security_log_element) == expected_elements

    log_file_elements = security_log_element.findall(_logging._FILE_TAG)
    if log_file:
        assert len(log_file_elements) == 1
    else:
        assert len(log_file_elements) == 0

    distribute_elements = security_log_element.findall(_logging._DISTRIBUTE_TAG)
    assert distribute_elements[0].text == str(distribute).lower()

    verbosity_elements = security_log_element.findall(_logging._VERBOSITY_TAG)
    assert len(verbosity_elements) == 1
    assert verbosity_elements[0].text == _logging.Verbosity.ERROR.name

    qos_elements = security_log_element.findall(_logging._QOS_TAG)
    assert len(qos_elements) == 1
    assert len(qos_elements[0]) == 0


def test_enable_logging_all(keystore_dir):
    assert cli.main(argv=['security', 'enable_logging', keystore_dir, '--distribute']) == 0

    test1_logging_config_path = pathlib.Path(f'{keystore_dir}/test1/logging.xml')
    test2_logging_config_path = pathlib.Path(f'{keystore_dir}/test2/logging.xml')
    assert test1_logging_config_path.exists()
    assert test2_logging_config_path.exists()

    for logging_config_path in (test1_logging_config_path, test2_logging_config_path):
        security_log_element = lxml.etree.parse(
            str(logging_config_path), lxml.etree.XMLParser(remove_comments=True)).getroot()
        assert security_log_element.tag == _logging._SECURITY_LOG_TAG
        assert len(security_log_element) == 3

        log_file_elements = security_log_element.findall(_logging._FILE_TAG)
        assert len(log_file_elements) == 0

        distribute_element = security_log_element.findall(_logging._DISTRIBUTE_TAG)
        assert len(distribute_element) == 1
        assert distribute_element[0].text == 'true'

        verbosity_element = security_log_element.findall(_logging._VERBOSITY_TAG)
        assert len(verbosity_element) == 1
        assert verbosity_element[0].text == _logging.Verbosity.ERROR.name

        qos_elements = security_log_element.findall(_logging._QOS_TAG)
        assert len(qos_elements) == 1
        assert len(qos_elements[0]) == 0


def test_enable_logging_verbosity(keystore_dir):
    assert cli.main(argv=[
        'security', 'enable_logging', keystore_dir, '/test1', '--distribute',
        '--verbosity', 'WARNING']) == 0

    logging_config_path = pathlib.Path(f'{keystore_dir}/test1/logging.xml')
    assert logging_config_path.exists()
    assert not pathlib.Path(f'{keystore_dir}/test2/logging.xml').exists()

    security_log_element = lxml.etree.parse(
        str(logging_config_path), lxml.etree.XMLParser(remove_comments=True)).getroot()
    assert security_log_element.tag == _logging._SECURITY_LOG_TAG
    assert len(security_log_element) == 3

    log_file_elements = security_log_element.findall(_logging._FILE_TAG)
    assert len(log_file_elements) == 0

    distribute_elements = security_log_element.findall(_logging._DISTRIBUTE_TAG)
    assert distribute_elements[0].text == 'true'

    verbosity_elements = security_log_element.findall(_logging._VERBOSITY_TAG)
    assert len(verbosity_elements) == 1
    assert verbosity_elements[0].text == _logging.Verbosity.WARNING.name

    qos_elements = security_log_element.findall(_logging._QOS_TAG)
    assert len(qos_elements) == 1
    assert len(qos_elements[0]) == 0


def test_enable_logging_invalid_verbosity(keystore_dir, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(argv=[
            'security', 'enable_logging', keystore_dir, '/test1', '--distribute',
            '--verbosity', 'INVALID'])
    assert e.value.code != 0
    stderr = capsys.readouterr().err.strip()
    assert "invalid choice: 'INVALID'" in stderr


def test_enable_logging_without_keystore(capsys):
    assert cli.main(argv=['security', 'enable_logging', '/non-existent', '--distribute']) != 0
    stderr = capsys.readouterr().err.strip()
    assert "'/non-existent' is not a valid keystore" in stderr
