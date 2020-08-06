"""Compile all of the YARA rules into a single binary file."""
import os
import re
from typing import Generator

import yara

RULES_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.


def _find_yara_files() -> Generator[str, None, None]:
    """Find all .yar[a] files in the rules directory.

    Yields:
        YARA rule filepaths, relative to the rules root directory.
    """
    for root, _, files in os.walk(RULES_DIR):
        for filename in files:
            lower_filename = filename.lower()
            if lower_filename.endswith('.yar') or lower_filename.endswith('.yara'):
                yield os.path.relpath(os.path.join(root, filename), start=RULES_DIR)


def copy_rules(target_path: str) -> None:
    """Copy YARA rules into a single rules file.

    Args:
        target_path: Where to save the aggregated rules file.
    """
    # Each rule file must be keyed by an identifying "namespace"; in our case the relative path.
    yara_filepaths = {relative_path: os.path.join(RULES_DIR, relative_path)
                      for relative_path in _find_yara_files()}

    # Compile all available YARA rules to verify their syntax
    yara.compile(
        filepaths=yara_filepaths,
        externals={'extension': '', 'filename': '', 'filepath': '', 'filetype': ''})

    dir = os.path.dirname(target_path)
    if dir != "":
        os.makedirs(dir, exist_ok=True)

    with open(target_path, mode='w') as target:
        while len(yara_filepaths) > 0:
            _copy_file(target, yara_filepaths, next(iter(yara_filepaths)))

    # Recompile to verify all includes have been copied successfully
    yara.compile(
        filepath=target_path,
        externals={'extension': '', 'filename': '', 'filepath': '', 'filetype': ''})

INCLUDE_REGEX = re.compile(r'^include\s+\"(.+?(?<!\\))\"')

def _copy_file(target, yara_filepaths, rel_path):
    if rel_path not in yara_filepaths:
        return
    with open(yara_filepaths[rel_path], mode='r') as source:
        for line in source:
            include_match = INCLUDE_REGEX.match(line)
            if include_match is not None:
                filename = include_match.group(1)
                filename.replace('\\"', '"')
                filename.replace('\\\\', '\\')
                if not os.path.isabs(filename):
                    filename = os.path.join(os.path.dirname(yara_filepaths[rel_path]), filename)
                rel_includepath = os.path.relpath(filename, start=RULES_DIR)
                _copy_file(target, yara_filepaths, rel_includepath)
            else:
                target.write(line)
    del yara_filepaths[rel_path]
