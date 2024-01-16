"""Wrapper around YARA analysis."""
import collections
import re
import requests
import subprocess
from typing import List

from lambda_functions.analyzer.common import LOGGER

# YARA matches from both yara-python and yextend are stored in this generic YaraMatch tuple.
YaraMatch = collections.namedtuple(
    'YaraMatch',
    [
        'rule_name',        # str: Name of the YARA rule
        'rule_namespace',   # str: Namespace of YARA rule (original YARA filename)
        'rule_metadata',    # Dict: String metadata associated with the YARA rule
        'matched_strings',  # Set: Set of string string names matched (e.g. "{$a, $b}")
        'matched_data'      # Set: Matched YARA data
    ]
)

RULE_COUNT_REGEX = re.compile("Info Successfully compiled ([0-9]+) default YARA rules")

class YaraAnalyzer:
    """Encapsulates YARA analysis and matching functions."""

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self.proc = None
        self._rule_count = 0

    def _start_thor_server(self):
        """Starts the THOR server."""
        LOGGER.info('Starting THOR server')
        self.proc = subprocess.Popen(
            ['./thor-linux-64', '--thunderstorm', '--pure-yara',  
             '--nothordb',  '--nolog', '--nocsv'], 
            stdout=subprocess.PIPE, universal_newlines=True
        )
        startup_successful = False
        while not startup_successful and self.proc.poll() is None:
            line = self.proc.stdout.readline()
            self.proc.stdout.flush()
            if "service started" in line:
                startup_successful = True
            rulecountmatch = RULE_COUNT_REGEX.search(line)
            if rulecountmatch is not None:
                self._rule_count = int(rulecountmatch.group(1))
            LOGGER.info(line)
        if not startup_successful:
            LOGGER.info(self.proc.stdout.read())
            raise Exception("THOR startup was not successful")
        LOGGER.info('Started THOR server')

    def __del__(self) -> None:
        if self.proc:
            self.proc.kill()

    @property
    def num_rules(self) -> int:
        """Count the number of YARA rules loaded in the analyzer."""
        return self._rule_count

    def analyze(self, target_file: str, original_target_path: str = '') -> List[YaraMatch]:
        """Run YARA analysis on a file.
        
        Args:
            target_file: Local path to target file to be analyzed.
            original_target_path: Path where the target file was originally discovered.
        
        Returns:
            List of YaraMatch tuples.
        """

        if self.proc is None:
            self._start_thor_server()

        thor_matches = []
        # THOR matches
        response = requests.post('http://127.0.0.1:8080/api/check', files=dict(file=open(target_file, 'rb')))
        if response.status_code == 200:
            messages = response.json()
            for message in messages:
                LOGGER.info("Received THOR log message: %s", str(message))
                if "matches" in message:
                    for match in message["matches"]:
                        try:
                            metadata = {
                                "description": match["reason"],
                                "reference": match["ref"],
                                "date": match["ruledate"],
                                "tags": ", ".join(match["tags"]),
                                "score": match["subscore"],
                            }
                            namespace = "THOR"
                            if "sigtype" in match and (match["sigtype"] == 1 or match["sigtype"] == "custom"):
                                namespace = "custom"
                            string_matches = match["matched"]
                            if string_matches is None:
                                string_matches = ["Unknown"]
                            thor_matches.append(YaraMatch(match["rulename"], namespace, metadata, set(["Unknown"]), set(string_matches)))
                        except (IndexError, KeyError): # THOR match with unexpected syntax
                            LOGGER.info("Could not parse THOR match: %s", str(match))
        response.close()
        return thor_matches


