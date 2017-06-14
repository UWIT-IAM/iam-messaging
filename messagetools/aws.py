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
# IAM messaging tools - AWS interface
#

from sys import exit
from copy import deepcopy

import logging
import json

from dao import AWS_DAO

class AWS(object):

    def __init__(self, conf):
        self._conf = conf
        
    # SNS actions

    def create_topic(self, name):
        dao = AWS_DAO(self._conf)
        response = dao.create_topic(name)
        return response

    def send_message(self, msg, context, cryptid, signid):
        dao = AWS_DAO(self._conf)
        response = dao.send_message(msg, context, cryptid, signid)
        return response

    def get_all_topics(self):
        dao = AWS_DAO(self._conf)
        response = dao.get_all_topics()
        return response


    # SQS actions

    def get_queue(self):
        dao = AWS_DAO(self._conf)
        response = dao.get_queue()
        return response

    def get_all_queues(self):
        dao = AWS_DAO(self._conf)
        response = dao.get_all_queues()
        return response

    def create_queue(self, name):
        dao = AWS_DAO(self._conf)
        response = dao.create_queue(name)
        return response

    def purge_queue(self, name):
        dao = AWS_DAO(self._conf)
        response = dao.purge_queue(name)
        return response

    def delete_queue(self, name):
        dao = AWS_DAO(self._conf)
        response = dao.delete_queue(name)
        return response

    def get_all_subscriptions_by_topic(self, name):
        dao = AWS_DAO(self._conf)
        response = dao.get_all_subscriptions_by_topic(name)
        return response

    def recv_message(self):
        dao = AWS_DAO(self._conf)
        response = dao.recv_message()
        return response

    def recv_and_process(self, handler, max=1):
        dao = AWS_DAO(self._conf)
        response = dao.recv_and_process(handler, max)
        return response
        

    # multi-actions

    def subscribe_queue(self, topic_name, queue_name):
        dao = AWS_DAO(self._conf)
        response = dao.subscribe_queue(topic_name, queue_name)
        return response

    def add_permission(self, topic_name, label, account, permission):
        dao = AWS_DAO(self._conf)
        response = dao.add_permission(topic_name, label, account, permission)
        return response


