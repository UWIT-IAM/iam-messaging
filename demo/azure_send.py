#
# IAM Azure send test
#

import json

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
from messagetools.ms_azure import Azure

import settings

import urllib3
urllib3.disable_warnings()

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

logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("azure event sender starting.")

crypt_init(settings.IAM_CONF)

msg = 'Hello, world, from py.'
if options.message!=None:
   msg = options.message

cryptkey = 'iamcrypt1'
if options.nocrypt:
   cryptkey = None

azure = Azure(settings.AZURE_CONF)
# azure = Azure(settings.AZURE_CONF_2)

for n in range(10):
  resp = azure.send_message(msg + ' - ' + str(n), 'Message with group u_spud.', cryptkey, 'iamsig1', properties={'Group-Stem':'u_spud'})
  print resp


