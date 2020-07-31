"""Unit tests for yara_analyzer.py. Uses fake filesystem."""
# pylint: disable=protected-access
import json
import os
import requests
import subprocess
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import yara_analyzer
from tests.lambda_functions.analyzer import thor_mocks

@mock.patch.dict(os.environ, values={'LAMBDA_TASK_ROOT': '/var/task'})
class YaraAnalyzerTest(fake_filesystem_unittest.TestCase):
    """Uses the real YARA library to parse the test rules."""

    def setUp(self):
        """For each test, build a new YaraAnalyzer."""
        self.setUpPyfakefs()
        with mock.patch.object(subprocess, 'Popen', side_effect=thor_mocks.mock_thor_start):
            self._analyzer = yara_analyzer.YaraAnalyzer()

        # Write target file.
        # pylint: disable=no-member
        self.fs.create_file('./target.exe', contents='This is definitely not an evil file. ^_^\n')

    @staticmethod
    def _rule_id(match):
        """Convert a YARA match into a string rule ID (file_name:rule_name)."""
        return '{}:{}'.format(match.rule_namespace, match.rule_name)

    @staticmethod
    def _assert_request(mock_requests: mock.MagicMock, mock_output: mock.MagicMock):
        """Verify the mocked request matches."""
        # Verify UPX call
        mock_output.assert_has_calls([
            mock.call(['./upx', '-q', '-d', mock.ANY], stderr=subprocess.STDOUT),
        ])
        mock_requests.assert_has_calls([
            mock.call('http://127.0.0.1:8080/api/check', files=mock.ANY)
        ])

    @mock.patch.object(subprocess, 'check_output')
    @mock.patch.object(requests, 'post', return_value=thor_mocks._THOR_MATCH)
    def test_analyze(self, mock_requests: mock.MagicMock, mock_output: mock.MagicMock):
        """Analyze returns the expected list of rule matches."""
        yara_matches = self._analyzer.analyze('/target.exe')
        self._assert_request(mock_requests, mock_output)
        self.assertEqual(1, len(yara_matches))

        match = yara_matches[0]
        self.assertEqual('THOR', match.rule_namespace)
        self.assertEqual('Example_Rule', match.rule_name)

    @mock.patch.object(subprocess, 'check_output')
    @mock.patch.object(requests, 'post', return_value=thor_mocks._THOR_NO_MATCHES)
    def test_analyze_no_matches(self, mock_requests: mock.MagicMock, mock_output: mock.MagicMock):
        """Analyze returns empty list if no matches."""
        self.assertEqual([], self._analyzer.analyze('/target.exe'))
        self._assert_request(mock_requests, mock_output)