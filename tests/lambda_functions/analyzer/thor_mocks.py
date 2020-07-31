from unittest import mock
from io import StringIO
import json
import requests

class PopenMock(object):
    def __init__(self):
        self.stdout = StringIO("Info: Init Successfully compiled 1 default YARA rules TYPE: YARA\nInfo: Server Server started, now send files to http://127.0.0.1:8080/api/check\n")

    def kill(self):
        pass
    def poll(self):
        return None

def mock_thor_start(*args, **kwargs):
    popen_mock = PopenMock()
    return popen_mock

_THOR_NO_MATCHES = requests.Response()
_THOR_NO_MATCHES.status_code = 200
_THOR_NO_MATCHES._content = b"[]"

_THOR_MATCH = requests.Response()
_THOR_MATCH.status_code = 200
_THOR_MATCH._content = json.dumps([
    {
        "lvl": "Alert",
        "mod": "Filescan",
        "msg": "Malware file found",
        "context": {
            "file": "path/to/file",
            "rulename_1": "Example_Rule",
            "reason_1": "Yara rule Example_Rule / Rule description",
            "ref_1": "Rule reference",
            "ruledate_1": "",
            "tags_1": "EXAMPLETAG HKTL",
            "subscore_1": "75",
            "matched_1": 'Str1: "example match"'
        }
    }
]).encode()
