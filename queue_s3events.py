#!/usr/bin/env python

import argparse, boto3, json, os, sys, time

class SnsRunner:
    def __init__(self):
        self.client_sqs = boto3.client('sqs')

    def __init_handle(self):
        self.handle = open(self.file_path)

        i = 0

        while i < (self.index or 0):
            self.handle.readline()
            i += 1

        return True

    def get_files(self):

        files = []

        i = 0

        while len(files) < self.count:
            f = self.handle.readline()

            if not f:
                break

            files.append(f.strip())

        old_index = self.index
        self.index += self.count
        self.log('Fetched %d entries starting at index %d (new index: %d)' % (len(files), old_index, self.index))

        return files

    def load(self, raw_args):
        parser = argparse.ArgumentParser(description='SNS S3-Event Sender')
        parser.add_argument('-b', dest='bucket', help='S3 bucket that listed keys can be found in.')
        parser.add_argument('-c', dest='count', type=int, help='Batch count')
        parser.add_argument('-f', dest='file_path', help='Input file path.')
        parser.add_argument('-i', dest='index', type=int, help='Starting index')
        parser.add_argument('-s', dest='sleep', type=int, help='Sleep time (seconds). If set, the script will loop through the input file in batches.')
        parser.add_argument('-q', dest='queue', help='SQS Queue to publish to')

        args = parser.parse_args(raw_args)
        self.bucket = args.bucket
        self.count = args.count
        self.file_path = args.file_path
        self.index = args.index
        self.sleep = args.sleep
        self.queue = args.queue

        good = True

        if not self.file_path:
            self.log_error('No file path given')
            good = False
        elif not os.path.isfile(self.file_path):
            self.log_error('File path not found: ' + self.file_path)
            good = False
        else:
            good = self.__init_handle() and good

        if self.count == -1:
            self.count = 300
        elif self.count <= 0:
            self.log_error('Count must be greater than 0.')
            good = False

        if self.index is not None and self.index < 0:
            self.log_error('Starting index must be greater than 0.')
            good = False

        if self.sleep is not None and self.sleep <= 0:
            self.log_error('Sleep time must be greater than 0.')
            good = False

        if not self.bucket:
            self.log_error('No bucket specified.')
            good = False

        if not self.queue:
            self.log_error('No queue specified.')
            good = False

        self.index = self.index or 0

        return good

    def log(self, msg):
        print('[%s]: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        sys.stdout.flush()

    def log_error(self, msg):
        self.log('(Error): ' + msg)

    def make_payload(self, current_file):
        return {
            "Records": [
                {
                    "eventVersion": "2.1",
                    "eventSource": "aws:s3",
                    "awsRegion": "us-east-1",
                    "eventTime": "2021-04-28T05:12:56.347Z",
                    "eventName": "ObjectCreated:Put",
                    "userIdentity": {
                        "principalId": "AWS:<Principal ID>"
                    },
                    "requestParameters": {
                    },
                    "responseElements": {
                    },
                    "s3": {
                        "s3SchemaVersion": "1.0",
                        "configurationId": "create",
                        "bucket": {
                            "name": self.bucket,
                            "ownerIdentity": {
                                "principalId": "<Principal ID>"
                            },
                            "arn": "arn:aws:s3:::" + self.bucket
                        },
                        "object": {
                            "key": current_file,
                            "size": 0,
                        }
                    }
                }
            ]
        }

    def process(self, files):
        for f in files:
            self.send(f)
        self.log('Sent %d SQS notices.' % len(files))

    def run(self):

        if (self.sleep or 0) < 0:
            # Single-run

            files = self.get_files()
            self.process(files)

        else:
            # Multi-run
            while True:
                files = self.get_files()

                if not files:
                    break

                self.process(files)

                if self.sleep:
                    self.log('Sleeping for %d seconds.' % self.sleep)
                    time.sleep(self.sleep)

    def send(self, current_file):
        payload = self.make_payload(current_file)

        sqs_args = {
            'QueueUrl': self.queue,
            'MessageBody': json.dumps(payload)
        }
        self.client_sqs.send_message(**sqs_args)

def main(raw_args):

    runner = SnsRunner()
    if not runner.load(raw_args):
        return 1

    try:
        runner.run()
    except KeyboardInterrupt:
        return 130

    return 0

if __name__ == '__main__':
    main(sys.argv[1:])