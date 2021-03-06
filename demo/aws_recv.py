#
# IAM AWS messaging tools
#
# sample sqs reciever
# boto3 version
#

import json

import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit
import signal
from optparse import OptionParser
import threading

from messagetools.iam_message import crypt_init
from messagetools.iam_message import decode_message
from messagetools.aws import AWS

import settings
import logging
import logging.config
logger = logging.getLogger()


# ----------- counters and etc ----------------

start_time = int(time.time()) + time.timezone
last_event_received = start_time
last_event_time = 0
num_events = 0

verbose = False


def save_message_and_exit(message):
    f = open('failed_message.txt', 'a')
    f.write(message)
    f.close()
    exit(1)


# ---------------- signal catcher ---


still_alive = True


def signal_handler(sig_num, frame):
    global still_alive
    if sig_num == signal.SIGINT:
        logger.info('Received interrupt signal')
    elif sig_num == signal.SIGUSR1:
        logger.info('Received USR1 signal')
    else:
        logger.info('Received signal %d' % (sig_num))
    still_alive = False


#
# ---------------- demo recv main --------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
parser.add_option('-m', '--max_messages', action='store', type='int', dest='maxmsg', help='maximum messages to process')
parser.add_option('', '--count', action='store_true', dest='count_only', help='just count the messages onthe queue', default=False)
parser.add_option('-q', '--queue', action='store', type='string', dest='queue', help='queue url')
parser.add_option('-l', '--log', action='store', type='string', dest='log', help='log name')
options, args = parser.parse_args()

max_messages = 10
if options.maxmsg:
    max_messages = options.maxmsg

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("aws event sender starting.")

crypt_init(settings.IAM_CONF)

logger.info('sws queue reader starting.')

# activate signal catcher
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGUSR1, signal_handler)

#
# process messages
#

# on empty queue:
#    sleep 1 minute for 10 minutes
# at 10 minutes idle
#    sleep 5 minutes

idle1 = 0  # 1 minute counter
idle5 = 0  # 5 minute counter

if options.queue is None:
    print('a queue url is required')
    sys.exit()

if options.verbose:
    verbose = True

logfile = None
if options.log is not None:
    logfile = open(options.log, 'a')


print('Listening on SQS queue ' + options.queue)
aws = AWS(settings.AWS_CONF)

nmsg = 0
while still_alive:

    status, msgs = aws.recv_message(options.queue)
    if msgs is None:
        sleep_sec = 300
        if idle5 > 0:
            idle5 += 1
            sleep_sec = 60
        else:
            idle1 += 1
            if idle1 >= 10:
                idle5 = 1
            sleep_sec = 10
        logging.debug('sleep %d seconds' % (sleep_sec))
        time.sleep(sleep_sec)
        continue

    idle1 = idle5 = 0

    if len(msgs) == 0:
        print('not iam?')
        continue

    handle, b64msg = msgs[0]

    msg = decode_message(b64msg)
    if msg is None:
        print('Not an iam message: ' + b64msg)
        aws.delete_message(options.queue, handle)
        continue

    hdr = msg[u'header']
    print('msg received: ' + hdr[u'timestamp'])
    if verbose:
        print(msg[u'header'])
    # print('uuid: ' + hdr[u'messageId'])
    if hdr[u'sender'] != 'gws':
        print('sender: ' + hdr[u'sender'])
    if verbose:
        print('contentType: ' + hdr[u'contentType'])
    if hdr[u'messageType'] == 'gws':
        context = json.loads(hdr[u'messageContext'])
        if 'group' in context:
            print('group: [%s]\n' % context['group'])
        if 'targets' in context:
            for tgt in context['targets']:
                print('target: ' + tgt['target'])
    if verbose:
        print('message: [%s]' % msg[u'body'])

    if logfile is not None:
        logfile.write('%s %s\n' % (hdr[u'timestamp'], msg[u'body']))

    aws.delete_message(options.queue, handle)

    nmsg += 1
    if nmsg == max_messages:
        break

logger.info('Exiting')
print('%d messages processed' % (nmsg))
