#
# IAM AWS messaging tools
#
# sig tester
#

import json

import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit

import threading

import logging.config

from messagetools.iam_message import crypt_init
from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message

import settings

#
# ---------------- gws_ce main --------------------------
#


logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("sig tester starting.")

crypt_init(settings.IAM_CONF)

# msg = 'Hello, world, from sigtest.py!\nAnother line.'
msg = 'Hello, world, from py.'

sigkey = 'iamsig1'
cryptkey = 'iamcrypt2'

# saving to a file allow easier intra-language verifications

a = encode_message(msg, 'spud', cryptkey, sigkey)
with open('sigtest.enc','w') as f:
    f.write(a)
    f.close()

# use the on eon file

with open('sigtest.enc','r') as f:
    b = f.read()

c = decode_message(b)
print (c)
msgout = c['body']
if msgout == msg:
    print ('Success')
else:
    print ('Fail')



