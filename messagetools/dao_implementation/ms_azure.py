#  ========================================================================
#  Copyright (c) 2015 The University of Washington
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  ========================================================================
#

#
# IAM messaging tools - DAO impl - Azure interface
#

import re
import json


# Azure interface classes - optional
import pkg_resources
packs = [package.project_name for package in pkg_resources.working_set]
if 'azure-servicebus' in packs:
    from azure.servicebus import ServiceBusService, Message, Topic, Rule, DEFAULT_RULE_NAME

from copy import deepcopy

from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message
from messagetools.dao_implementation.mock import get_mockdata_message

import logging
logger = logging.getLogger(__name__)

class File(object):

    def __init__(self, conf):
        self._conf = conf
        self._event_no = 0

    def recv_message(self):
        message = get_mockdata_message('ms_azure', self._conf, self._event_no)
        self._event_no += 1
        return message
    
    def recv_and_process(self, handler, max=1):
        ntot = 0
        nvalid = 0

        logger.debug('recv and proc: no=%d, max=%d' % (self._event_no, max))
        for n in range(0,max):
           message = get_mockdata_message('ms_azure', self._conf, self._event_no)
         
           if message==None: 
               break
           self._event_no += 1
           ret = handler(message)
           if ret:
               nvalid += 1
           ntot += 1
        return (ntot, nvalid)
    
    

class Live(object):

    def __init__(self, conf):
        self._conf = conf
        self._topic = conf['TOPIC_NAME']
        self._subscr = conf['SUBSCRIPTION_NAME']
        self._bus_service = ServiceBusService(service_namespace=self._conf['NAMESPACE'],
                                 shared_access_key_name=self._conf['ACCESS_KEY_NAME'],
                                 shared_access_key_value=self._conf['ACCESS_KEY_VALUE'])


    def _get_bus_service(self):
        return ServiceBusService(service_namespace=self._conf['NAMESPACE'],
                                 shared_access_key_name=self._conf['ACCESS_KEY_NAME'],
                                 shared_access_key_value=self._conf['ACCESS_KEY_VALUE'])

    def send_message(self, msg, context, cryptid, signid, properties={}):
        # bus_service = self._get_bus_service()
        b64msg = encode_message(msg, context, cryptid, signid)
        ms_msg = Message(b64msg, custom_properties=properties)
        ret = self._bus_service.send_topic_message(self._conf['TOPIC_NAME'], ms_msg)
        return ret

    def create_topic(self, topic_name):
        bus_service = self._get_bus_service()
        bus_service.create_topic(topic_name)

    def create_subscription(self, topic_name, name):
        bus_service = self._get_bus_service()
        ret = bus_service.create_subscription(topic_name, name)
        print (ret)

    def recv_message(self, peek=False):
        subscription_name=self._conf['SUBSCRIPTION_NAME']
        topic_name = self._conf['TOPIC_NAME']
        bus_service = self._get_bus_service()
        ms_msg = bus_service.receive_subscription_message(topic_name, subscription_name, peek_lock=peek)
        msg = decode_message(ms_msg.body)
        if peek:
            return (msg, ms_msg.delete, ms_msg.unlock)
        else:
            return msg
    
    def recv_and_process(self, handler, max=1):
        bus_service = self._get_bus_service()
        nm = 0
        for m in range(0,max):
            print ('receive_subscription_message: call')
            ms_msg = bus_service.receive_subscription_message(self._topic, self._subscr, peek_lock=True, timeout='3')
            print ('receive_subscription_message: return')
            if ms_msg is None or ms_msg.body is None:
                print ('no more messages')
                return nm
            nm += 1
            dmsg = decode_message(ms_msg.body)
            if dmsg is None:
                print ('removing invalid message')
                ms_msg.delete()
                continue
            ret = handler(decode_message(ms_msg.body))
            if ret:
                print ('deleting')
                ms_msg.delete()
                print ('deleted')
            else:
                ms_msg.unlock()
        return nm

    def add_rule(self, topic_name, subscription_name, rule_name, rule_value):
        bus_service = self._get_bus_service()
        rule = Rule()
        rule.filter_type = 'SqlFilter'
        rule.filter_expression = rule_value
        ret = bus_service.create_rule(topic_name, subscription_name, rule_name, rule)
        print (ret)

    def remove_rule(self, topic_name, subscription_name, rule_name):
        if rule_name == '-default-':
            rule_name = DEFAULT_RULE_NAME
        bus_service = self._get_bus_service()
        ret = bus_service.delete_rule(topic_name, subscription_name, rule_name)
        print (ret)

