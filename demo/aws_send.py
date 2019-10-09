#
# IAM AWS messaging tools
#
# sample sns sender
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

from messagetools.iam_message import crypt_init
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
parser.add_option('-n', '--nocrypt', action='store_true', dest='nocrypt', default='false', help='dont encrypt message')
options, args = parser.parse_args()

print(logging)

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("aws event sender starting.")

crypt_init(settings.IAM_CONF)

msg = 'Hello, world, from py..'
if options.message!=None:
   msg = options.message

cryptkey = 'iamcrypt1'
if options.nocrypt:
   cryptkey = None

aws = AWS(settings.AWS_CONF)

aws.send_message(msg, 'something specific to the test', cryptkey, 'iamsig1')


