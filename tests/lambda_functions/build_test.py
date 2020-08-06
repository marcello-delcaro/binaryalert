"""Test lambda_functions/build.py."""
import os
import tempfile
from typing import List, Set
import unittest
from unittest import mock
import zipfile

from lambda_functions import build


def _mock_pip_main(args_list: List[str]) -> None:
    """Mock pip install just creates the target directories."""
    install_directory = args_list[6]
    requirements_file = args_list[8]
    with open(requirements_file) as f:
        for pkg in f:
            pkg_name = pkg.split('/')[-1].split('==')[0].split('@')[0]
            os.makedirs(os.path.join(install_directory, pkg_name))


@mock.patch.object(build, 'print')
class BuildTest(unittest.TestCase):
    """Test top-level build command."""
    # pylint: disable=protected-access

    def setUp(self):
        """Find temp directory in which to build packages."""
        self.maxDiff = None  # pylint: disable=invalid-name
        self._tempdir = tempfile.gettempdir()

    def _verify_filenames(self, archive_path: str, expected_filenames: Set[str],
                          subset: bool = False):
        """Verify the set of filenames in the zip archive matches the expected list."""
        with zipfile.ZipFile(archive_path, 'r') as archive:
            filenames = set(zip_info.filename for zip_info in archive.filelist)

        if subset:
            self.assertTrue(expected_filenames.issubset(filenames))
        else:
            self.assertEqual(expected_filenames, filenames)

    @mock.patch.object(build.subprocess, 'check_call', side_effect=_mock_pip_main)
    def test_build_all(self, mock_pip: mock.MagicMock, mock_print: mock.MagicMock):
        """Verify list of bundled files for each Lambda function."""
        build.build(self._tempdir, downloader=True)

        self._verify_filenames(
            os.path.join(self._tempdir, 'lambda_analyzer.zip'),
            {
                # Python source files
                'lambda_functions/__init__.py',
                'lambda_functions/analyzer/__init__.py',
                'lambda_functions/analyzer/analyzer_aws_lib.py',
                'lambda_functions/analyzer/binary_info.py',
                'lambda_functions/analyzer/common.py',
                'lambda_functions/analyzer/file_hash.py',
                'lambda_functions/analyzer/main.py',
                'lambda_functions/analyzer/yara_analyzer.py',

                # Compiled rules file
                'custom-signatures/yara/custom-rules.yar',

                # Natively compiled binaries
                'thor-linux-64',
                'upx',

                # Licenses
                'UPX_LICENSE',
                'docs/License_Acknowledgement.txt',
            },
            subset=True
        )

        self._verify_filenames(
            os.path.join(self._tempdir, 'lambda_downloader.zip'),
            {
                # Python source files
                'lambda_functions/',
                'lambda_functions/__init__.py',
                'lambda_functions/downloader/',
                'lambda_functions/downloader/__init__.py',
                'lambda_functions/downloader/main.py',

                # Libraries (mock install)
                'cbapi-python.git/',
                'prompt-toolkit/',
                'python-dateutil/'
            }
        )

        mock_pip.assert_called_once()
        mock_print.assert_called()
