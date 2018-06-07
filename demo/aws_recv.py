#
# IAM AWS messaging tools
#
# sample sqs reciever
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
logger = logging.getLogger()

from messagetools.iam_message import crypt_init
from messagetools.aws import AWS

import settings

# ----------- counters and etc ----------------

start_time = int(time.time()) + time.timezone
last_event_received = start_time
last_event_time = 0
num_events = 0


# -------------------------------------
#
def save_message_and_exit(message):
   f = open('failed_message.txt','a')
   f.write(message)
   f.close()
   exit(1) 




# ---------------- signal catcher ---

still_alive = True
def signal_handler(sig_num, frame):
   global still_alive
   if sig_num==signal.SIGINT:
      logger.info('Received interrupt signal')
   elif sig_num==signal.SIGUSR1:
      logger.info('Received USR1 signal')
   else:
      logger.info('Received signal %d' %(sig_num))
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
parser.add_option('-q', '--queue', action='store', type='string', dest='queue', help='queue name')
options, args = parser.parse_args()

max_messages = 10
if options.maxmsg: max_messages = options.maxmsg

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

if options.queue is not None:
   settings.AWS_CONF['SQS_QUEUE'] = options.queue

print('Listening on SQS queue ' + settings.AWS_CONF['SQS_QUEUE'])
aws = AWS(settings.AWS_CONF)

nmsg = 0
while still_alive:

   message = aws.recv_message()
   # print (message)
   if message==None: 
      sleep_sec = 300
      if idle5>0:
         idle5 += 1
         sleep_sec = 60
      else:
         idle1 += 1 
         if idle1>=10: idle5 = 1
         sleep_sec = 10
      logging.debug('sleep %d seconds' % (sleep_sec))
      time.sleep(sleep_sec)
      continue
    
   idle1 = idle5 = 0     
   # print(message[u'header'])
   hdr = message[u'header']
   print ('message received: ' + hdr[u'timestamp'])
   # print ('uuid: ' + hdr[u'messageId'])
   if hdr[u'sender'] != 'gws':
       print ('sender: ' + hdr[u'sender'])
   # print ('contentType: ' + hdr[u'contentType'])
   context = json.loads(hdr[u'messageContext'])
   if 'group' in context:
       print ('group: [%s]\n' % context['group'])
   # print ('message: [%s]' % message[u'body'])

   nmsg += 1
   if nmsg==max_messages:
      break

logger.info('Exiting')
print ('%d messages processed' %(nmsg))

