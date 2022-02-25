#!/usr/bin/env python3

# Usage A: ./script.py list <bucket-name> <output-file>
# Usage B: ./script.py run <bucket-name> <input-file> [batch-size]

import botocore, boto3, json, sys, time

# error() source: https://realpython.com/python-print/
from functools import partial
redirect = lambda function, stream: partial(function, file=stream)
prefix = lambda function, prefix: partial(function, prefix)
error = prefix(redirect(print, sys.stderr), '[ERROR]')

class Runner:

    def __get_path_input(self):
        return self.__path_input

    def __get_path_problems(self):
        return "%s.problems" % self.path_input

    def __get_path_session(self):
        return "%s.session" % self.path_input

    def __get_path_unresulted(self):
        return "%s.unresulted" % self.path_input

    def __set_path_input(self, value):
        self.__path_input = value
        self.load_session()

    def __init__(self):
        config = botocore.config.Config(read_timeout=900, connect_timeout=900, retries = {'max_attempts': 3})
        self.session = boto3.Session()
        self.client_lambda = self.session.client('lambda', config=config)
        self.client_s3 = boto3.client('s3')
        self.bad = []

    def append_problems(self, keys):
        with open(self.path_problems, 'a') as f:
            f.writelines(k + "\n" for k in keys)

    def append_unresulted(self, keys):
        with open(self.path_unresulted, 'a') as f:
            f.writelines(k + "\n" for k in keys)

    def get_input_keys(self):
        if not self.input_handle:
            self.input_handle = open(self.path_input, 'r')
            for i in range(self.rows_read):
                self.input_handle.readline()

        return [x.strip() for x in [self.input_handle.readline() for i in range(self.batch_size)] if x.strip()]

    def get_listings(self, bucket, token = None):

        kwargs = {
            'Bucket': bucket
        }
        if token:
            kwargs['ContinuationToken'] = token

        self.log('Fetching S3 records.')

        response = self.client_s3.list_objects_v2(**kwargs)

        items = [i['Key'] for i in response['Contents'] if i.get('Size', 0) > 0]

        self.log('Fetched %d items.' % len(items))

        return items, response.get('NextContinuationToken')

    def load_session(self):
        try:
            with(open(self.path_session)) as f:
                j = json.load(f)
                r = j.get('RowsRead', 0)
        except:
            r = 0

        self.rows_read_initial = self.rows_read = r

    def invoke(self, bucket, keys):

        payload = {
            'BucketName': bucket,              # S3 bucket name
            'EnableSNSAlerts': False,          # Toggle SNS alerts
            'ObjectKeys': keys                 # List of S3 object keys
        }

        kwargs = {
            'FunctionName': '<function>_binaryalert_analyzer',
            'Payload': json.dumps(payload),
            'Qualifier': 'Production'
        }

        response = self.client_lambda.invoke(**kwargs)
        results = json.load(response['Payload'])

        if 'errorMessage' in results:
            if 'No space left on device' in results['errorMessage']:

                # Note problems for later
                self.append_problems(keys)

                self.log('One of these is too large for the lambda: %s' % ' '.join(keys))
                return 0
            else:
                msg = 'Batch failed (%s). %d items attempted: %s' % (results['errorMessage'], len(keys), ', '.join(keys))
                self.log('Fatal error. %s' % msg)
                return 0
                raise TryAgainException(msg)

        resulted = [':'.join(x.split(':')[2:]) for x in results.keys()]
        unresulted = [x for x in keys if x not in resulted]
        if unresulted:
            self.append_unresulted(unresulted)

        return len(results.keys())

    def invoke_outer(self, bucket, keys, chunk_size = 10, increment = True):
        for chunk in [keys[x:x+chunk_size] for x in range(0, len(keys), chunk_size)]:
            if increment:
                self.total += len(chunk)
                success = False
                for i in range(3):
                    try:
                        self.count += self.invoke(bucket, chunk)
                        success = True
                        break
                    except TryAgainException:
                        t = 900
                        self.log('Sleeping for %d seconds and trying again.' % t)
                        time.sleep(t)
                        self.log('Got stuck here: %s' % ' '.join(keys))
                if not success:
                    raise Exception('Repeated fails.')

                msg = 'Processed: %d/%d' % (self.count, self.total)
                if self.rows_read_initial:
                    msg += ' (starting from line %d)' % self.rows_read_initial
                self.log(msg)

    def log(self, msg):
        print('[%s]: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        sys.stdout.flush()

    def log_error(self, msg):
        error('[%s]: %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        sys.stderr.flush()

    path_input = property(__get_path_input, __set_path_input)
    path_problems = property(__get_path_problems)
    path_session = property(__get_path_session)
    path_unresulted = property(__get_path_unresulted)

    def run(self, args):

        mode_run = 'run'
        mode_list = 'list'
        modes = [mode_run, mode_list]

        if len(args) < 1 or args[0] not in modes:
            self.log_error('No mode selected. Valid: %s' % ', '.join(modes))
            return 1

        if args[0] == mode_list:
            return self.run_list(args[1:])
        if args[0] == mode_run:
            return self.run_run(args[1:])

    def run_list(self, args):

        good = True
        if not args or not args[0]:
            self.log_error('No bucket defined')
            good = False

        if len(args) < 2 or not args[1]:
            self.log_error('No output file defined')
            good = False

        if not good:
            return 1

        first = True
        token = None
        total = 0

        with open(args[1], 'w') as f:
            while first or token:
                first = False
                keys, token = self.get_listings(args[0], token)
                total += len(keys)
                self.log('Total records read: %d' % total)
                f.writelines([k + "\n" for k in keys])

        return 0

    def run_run(self, args):

        good = True
        if not args or not args[0]:
            self.log_error('No bucket defined')
            good = False

        if len(args) < 2 or not args[1]:
            self.log_error('No input file defined')
            good = False

        if not good:
            return 1

        self.path_input = args[1]
        self.input_handle = None

        if len(args) > 2:
            self.batch_size = int(args[2])
        else:
            self.batch_size = 10

        self.count = 0
        self.total = 0

        try:
            while True:
                keys = self.get_input_keys()
                if not keys:
                    break
                self.invoke_outer(args[0], keys)
                self.rows_read += len(keys)
        except:
            raise
        finally:
            self.save_session()
            # Dispose of input handler
            if self.input_handle:
                self.input_handle.close()


        if self.bad:
            bad = self.bad
            self.bad = []
            self.invoke_outer(bucket, bad, 1, False)
            

        if self.bad:
            print('The following hashes yielded a "No space left on device" error:', ' '.join(self.bad))

    def save_session(self):
        with open(self.path_session, 'w') as f:
            obj = {
                'RowsRead': self.rows_read
            }
            json.dump(obj, f)

class TryAgainException(Exception):
    pass

if __name__ == '__main__':
    try:
        r = Runner()
        exit_code = r.run(sys.argv[1:])
    except KeyboardInterrupt:
        exit(130)

