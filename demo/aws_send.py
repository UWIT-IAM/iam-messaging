#
# IAM AWS messaging tools
#
# sample sns sender
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

import logging
import logging.config

from messagetools.iam_message import crypt_init
from messagetools.iam_message import encode_message
from messagetools.aws import AWS

import settings

#
# ---------------- gws_ce main --------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-m', '--message', action='store', type='string', dest='message', help='message')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
parser.add_option('', '--crypt', action='store', dest='cryptid', default='iamcrypt1', help='encrypt id')
parser.add_option('-n', '--nocrypt', action='store_true', dest='nocrypt', default=False, help='dont encrypt message')
parser.add_option('-a', '--arn', action='store', dest='arn', default='json-test-1', help='sns arn')
options, args = parser.parse_args()

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("aws event sender starting.")

crypt_init(settings.IAM_CONF)

msg = 'Hello, world, from py..'
if options.message is not None:
    msg = options.message

cryptid = 'iamcrypt2'
if options.cryptid:
    cryptid = options.cryptid
if options.nocrypt:
    cryptid = None

arn = options.arn

aws = AWS(settings.AWS_CONF)

signid = 'iamsig1'
context = 'something specific to the test'
b64msg = encode_message(msg, context, cryptid, signid)

attrs = {'iam_attrs_1': {'DataType': 'String', 'StringValue': 'test aws_send'}, 'iam_attrs_2': {'DataType': 'String', 'StringValue': 'boto3 '}}
aws.send_message(b64msg, arn=arn, attributes=attrs)
