#
# IAM AWS messaging tools
#
# sample sqs reciever
#

# json classes
import simplejson as json

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

# syslog shortcuts
import syslog

log=syslog.syslog
log_debug=syslog.LOG_DEBUG
log_info=syslog.LOG_INFO
log_err=syslog.LOG_ERR
log_alert=syslog.LOG_ALERT

from iam_msglib.msglib import iam_init
from iam_msglib.aws import iam_aws_recv_message



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
      log(log_info, 'Received interrupt signal')
   elif sig_num==signal.SIGUSR1:
      log(log_info, 'Received USR1 signal')
   else:
      log(log_info, 'Received signal %d' %(sig_num))
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
options, args = parser.parse_args()

max_messages = 0
if options.maxmsg: max_messages = options.maxmsg

config_file = 'etc/aws.conf.js'
if options.config!=None:
   config_file = options.config
   print 'using config=' + config_file
f = open(config_file,'r')

config = json.loads(f.read())

iam_init(config)

# logging
log_facility = syslog.LOG_SYSLOG
logf = config['syslog_facility']
if re.match(r'LOG_LOCAL[0-7]', logf): log_facility = eval('syslog.'+logf)

logname = 'demo_recv'
if 'log_name' in config: logname = config['log_name']
syslog.openlog(logname, syslog.LOG_PID, log_facility)
log(log_info, "sws queue monitor starting.  (conf='%s')" % (options.config))

if options.count_only: exit()

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


nmsg = 0
while still_alive:

   message = iam_aws_recv_message()
   if message==None: 
      sleep_sec = 1800
      if idle5>0:
         idle5 += 1
         sleep_sec = 300
      else:
         idle1 += 1 
         if idle1>=10: idle5 = 1
         sleep_sec = 60
      log(log_debug, 'sleep %d seconds' % (sleep_sec))
      time.sleep(sleep_sec)
      continue
    
   idle1 = idle5 = 0     
   hdr = message[u'header']
   print 'message received: type: ' + hdr[u'messageType']
   print 'uuid: ' + hdr[u'messageId']
   print 'sent: ' + hdr[u'timestamp']
   print 'sender: ' + hdr[u'sender']
   print 'contentType: ' + hdr[u'contentType']
   print 'context: [%s]' % hdr[u'messageContext']
   print 'message: [%s]' % message[u'body']

   nmsg += 1
   if nmsg==max_messages:
      break

log(log_info, 'Exiting')
print '%d messages processed' %(nmsg)

