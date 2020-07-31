"""Unit tests for analyzer main.py. Mocks out filesystem and boto3 clients."""
import hashlib
import json
import os
import requests
import subprocess
from unittest import mock
import urllib.parse

from pyfakefs import fake_filesystem_unittest

from tests import common
from tests.lambda_functions.analyzer import thor_mocks

# Mock S3 bucket and objects.
MOCK_S3_BUCKET_NAME = 'mock-bucket'
FILE_MODIFIED_TIME = 'test-last-modified'
GOOD_FILE_CONTENTS = 'Hello, world!\n'
GOOD_FILE_METADATA = {'filepath': 'win32'}
GOOD_S3_OBJECT_KEY = 'space plus+file.test'
EVIL_FILE_CONTENTS = 'Hello, evil world!\n'
EVIL_FILE_METADATA = {'filepath': '/path/to/mock-evil.exe'}
EVIL_S3_OBJECT_KEY = 'evil.exe'

MOCK_DYNAMO_TABLE_NAME = 'mock-dynamo-table'
MOCK_SNS_TOPIC_ARN = 's3:mock-sns-arn'

# Mimics minimal parts of S3:ObjectAdded event that triggers the lambda function.
LAMBDA_VERSION = 1
TEST_CONTEXT = common.MockLambdaContext(LAMBDA_VERSION)

class MockS3Object:
    """Simple mock for boto3.resource('s3').Object"""
    def __init__(self, bucket_name, object_key):
        self.name = bucket_name
        self.key = object_key

    def download_file(self, download_path):
        with open(download_path, 'w') as f:
            f.write(GOOD_FILE_CONTENTS if self.key == GOOD_S3_OBJECT_KEY else EVIL_FILE_CONTENTS)

    @property
    def last_modified(self):
        return FILE_MODIFIED_TIME

    @property
    def metadata(self):
        return GOOD_FILE_METADATA if self.key == GOOD_S3_OBJECT_KEY else EVIL_FILE_METADATA


@mock.patch.dict(os.environ, values={
    'LAMBDA_TASK_ROOT': '/var/task',
    'YARA_MATCHES_DYNAMO_TABLE_NAME': MOCK_DYNAMO_TABLE_NAME,
    'YARA_ALERTS_SNS_TOPIC_ARN': MOCK_SNS_TOPIC_ARN
})
class MainTest(fake_filesystem_unittest.TestCase):
    """Test end-to-end functionality of the analyzer."""
    # pylint: disable=protected-access

    def setUp(self):
        """Before each test, create the mock environment."""
        # Show all differences on assertion failures, even for large dictionaries.
        self.maxDiff = None  # pylint: disable=invalid-name

        # Set up the fake filesystem.
        self.setUpPyfakefs()

        # Create test event.
        self._test_event = {
            'Records': [
                {
                    'body': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': MOCK_S3_BUCKET_NAME},
                                    'object': {'key': urllib.parse.quote_plus(GOOD_S3_OBJECT_KEY)}
                                }
                            }
                        ]
                    })
                },
                {
                    'body': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': MOCK_S3_BUCKET_NAME},
                                    'object': {'key': urllib.parse.quote_plus(EVIL_S3_OBJECT_KEY)}
                                }
                            }
                        ]
                    })
                }
            ]
        }

        # Import the module under test (now that YARA is mocked out).
        with mock.patch('boto3.client'), mock.patch('boto3.resource'), \
            mock.patch.object(subprocess, 'Popen', side_effect=thor_mocks.mock_thor_start):
            from lambda_functions.analyzer import main
            self.main = main

        # Reset each boto3 resource (sometimes necessary depending on import order).
        self.main.analyzer_aws_lib.CLOUDWATCH = mock.MagicMock()
        self.main.analyzer_aws_lib.DYNAMODB = mock.MagicMock()
        self.main.analyzer_aws_lib.S3 = mock.MagicMock()
        self.main.analyzer_aws_lib.SNS = mock.MagicMock()

        # Mock S3 Object
        self.main.analyzer_aws_lib.S3.Object = MockS3Object

    def test_objects_to_analyze_simple(self):
        """Test event parsing for a simple/direct invocation event."""
        event = {
            'BucketName': 'bucket1',
            'EnableSNSAlerts': True,
            'ObjectKeys': ['key1', 'key2', 'key3']
        }

        result = list(self.main._objects_to_analyze(event))
        expected = [
            ('bucket1', 'key1'),
            ('bucket1', 'key2'),
            ('bucket1', 'key3')
        ]
        self.assertEqual(expected, result)

    def test_objects_to_analyze_sqs_event(self):
        """Test event parsing when invoked from dispatcher with SQS messages."""
        event = {
            'Records': [
                {
                    'body': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'bucket1'},
                                    'object': {'key': 'key1'}
                                }
                            },
                            {
                                's3': {
                                    'bucket': {'name': 'bucket1'},
                                    'object': {'key': 'key2'}
                                }
                            }
                        ]
                    }),
                    'receipt': 'receipt1',
                    'receive_count': 1
                },
                {
                    'body': json.dumps({  # Invalid SQS message should be skipped
                        'Bucket': 'bucket-name',
                        'Event': 's3:TestEvent',
                        'Service': 'Amazon S3',
                        'Time': 'now'
                    })
                },
                {
                    'body': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'bucket2'},
                                    'object': {'key': 'key3'}
                                }
                            }
                        ]
                    }),
                    'receipt': 'receipt2',
                    'receive_count': 2
                }
            ],
            'queue_url': 'url'
        }

        with mock.patch.object(self.main, 'LOGGER') as mock_logger:
            result = list(self.main._objects_to_analyze(event))
            mock_logger.assert_has_calls([
                mock.call.exception('Skipping invalid SQS message %s', mock.ANY)
            ])

        expected = [
            ('bucket1', 'key1'),
            ('bucket1', 'key2'),
            ('bucket2', 'key3')
        ]
        self.assertEqual(expected, result)

    @mock.patch.object(subprocess, 'check_call')
    @mock.patch.object(subprocess, 'check_output')
    @mock.patch.object(requests, 'post', side_effect=[thor_mocks._THOR_NO_MATCHES, thor_mocks._THOR_MATCH])
    def test_analyze_lambda_handler(self, mock_post: mock.MagicMock, mock_output: mock.MagicMock, mock_call: mock.MagicMock):
        """Verify return value, logging, and boto3 calls when multiple files match YARA rules."""
        with mock.patch.object(self.main, 'LOGGER') as mock_logger:
            result = self.main.analyze_lambda_handler(self._test_event, TEST_CONTEXT)
            # Verify logging statements.
            mock_logger.assert_has_calls([
                mock.call.info('Analyzing "%s:%s"', MOCK_S3_BUCKET_NAME, GOOD_S3_OBJECT_KEY),
                mock.call.info(
                    '%s did not match any YARA rules',
                    mock.ANY),
                mock.call.info('Analyzing "%s:%s"', MOCK_S3_BUCKET_NAME, EVIL_S3_OBJECT_KEY),
                mock.call.warning(
                    '%s matched YARA rules: %s',
                    mock.ANY,
                    {'THOR:Example_Rule'}
                )
            ])

            # Verify 2 UPX calls
            mock_output.assert_has_calls([
                mock.call(['./upx', '-q', '-d', mock.ANY], stderr=subprocess.STDOUT),
            ] * 2)

            # Verify 2 shred calls
            mock_call.assert_has_calls([
                mock.call(['shred', '--force', '--remove', mock.ANY])
            ] * 2)

        # Verify return value.
        good_s3_id = 'S3:{}:{}'.format(MOCK_S3_BUCKET_NAME, GOOD_S3_OBJECT_KEY)
        evil_s3_id = 'S3:{}:{}'.format(MOCK_S3_BUCKET_NAME, EVIL_S3_OBJECT_KEY)
        expected = {
            good_s3_id: {
                'FileInfo': {
                    'MD5': hashlib.md5(GOOD_FILE_CONTENTS.encode('utf-8')).hexdigest(),
                    'S3LastModified': FILE_MODIFIED_TIME,
                    'S3Location': good_s3_id,
                    'S3Metadata': GOOD_FILE_METADATA,
                    'SHA256': hashlib.sha256(GOOD_FILE_CONTENTS.encode('utf-8')).hexdigest()
                },
                'MatchedRules': {},
                'NumMatchedRules': 0
            },
            evil_s3_id: {
                'FileInfo': {
                    'MD5': hashlib.md5(EVIL_FILE_CONTENTS.encode('utf-8')).hexdigest(),
                    'S3LastModified': FILE_MODIFIED_TIME,
                    'S3Location': evil_s3_id,
                    'S3Metadata': EVIL_FILE_METADATA,
                    'SHA256': hashlib.sha256(EVIL_FILE_CONTENTS.encode('utf-8')).hexdigest()
                },
                'MatchedRules': {
                    'Rule1': {
                        'MatchedData': ['example match'],
                        'MatchedStrings': [],
                        'Meta': {
                            'description': 'Rule description',
                            'reference': 'Rule reference',
                            'tags': 'EXAMPLETAG HKTL',
                            'score': '75',
                            'date': '',
                        },
                        'RuleFile': 'THOR',
                        'RuleName': 'Example_Rule',
                    }
                },
                'NumMatchedRules': 1
            }
        }

        self.assertEqual(expected, result)

        # Verify that the return value can be encoded as JSON.
        json.dumps(result)

        # Verify that the Dynamo table was created.
        self.main.analyzer_aws_lib.DYNAMODB.assert_has_calls([
            mock.call.Table(MOCK_DYNAMO_TABLE_NAME)
        ])

        # Verify an SNS message was published.
        self.main.analyzer_aws_lib.SNS.assert_has_calls([
            mock.call.Topic(MOCK_SNS_TOPIC_ARN),
            mock.call.Topic().publish(
                Message=mock.ANY,
                Subject='[BinaryAlert] /path/to/mock-evil.exe matches a YARA rule'
            )
        ])

        # Verify the correct metrics were published to Cloudwatch.
        self.main.analyzer_aws_lib.CLOUDWATCH.assert_has_calls([
            mock.call.put_metric_data(
                MetricData=[
                    {
                        'MetricName': 'AnalyzedBinaries',
                        'Value': 2,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'MatchedBinaries',
                        'Value': 1,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'YaraRules',
                        'Value': 1,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'S3DownloadLatency',
                        'StatisticValues': {
                            'Minimum': mock.ANY,
                            'Maximum': mock.ANY,
                            'SampleCount': 2,
                            'Sum': mock.ANY
                        },
                        'Unit': 'Milliseconds'
                    }
                ],
                Namespace='BinaryAlert'
            )
        ])
