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
# boto3 edition
#

# SNS
# name is the last part
# delete and etc use topic_arn
# publish uses arn

# SQS
# queuename is last part
# create give back queueUrl, not arn
# list and etc return urls
# most ops use QueueUrl
# get url wants QueueName and QueueOwnerAWSAccountId

import re

import boto3
import json

from sys import exit
from copy import deepcopy

from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message
from messagetools.exceptions import TopicNotFoundException
from messagetools.exceptions import QueueNotFoundException
from messagetools.exceptions import ClientException

import logging
logger = logging.getLogger(__name__)

# factory limits and etc
# max message is presently 256K, but that includes any attributes, so we round down
sns_max_len = 260000
sns_default_subject = 'IAM Message'

# client error decorators


def safe_sqs(func):
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except boto3.client('sqs').exceptions.QueueDoesNotExist as e:
            raise QueueNotFoundException(' '.join(e.args))
        except boto3.client('sqs').exceptions.ClientError as e:
            raise ClientException(' '.join(e.args))
    return func_wrapper


def safe_sns(func):
    def func_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except boto3.client('sns').exceptions.NotFoundException:
            raise TopicNotFoundException(' '.join(e.args))
        except boto3.client('sns').exceptions.InvalidParameterException:
            raise ClientException(' '.join(e.args))
        except boto3.client('sns').exceptions.ClientError as e:
            raise ClientException(' '.join(e.args))
    return func_wrapper

# status from response


def _status(rsp):
    return rsp['ResponseMetadata']['HTTPStatusCode']


class AWS(object):

    def __init__(self, conf):
        self._conf = conf
        boto3.setup_default_session(region_name=conf['REGION'],
                                    aws_access_key_id=self._conf['DEFAULT_KEYID'],
                                    aws_secret_access_key=self._conf['DEFAULT_KEY'])

    # args:
    @safe_sns
    def send_message(self, b64msg, arn=None, subject=sns_default_subject, attributes={}):
        sns_client = boto3.client('sns')
        if arn is None:
            arn = self._conf['SNS_ARN']
        if len(b64msg) > sns_max_len:
            raise ClientException('Message too long for SNS send.')
        rsp = sns_client.publish(TopicArn=arn, Message=b64msg, Subject=subject, MessageStructure='string', MessageAttributes=attributes)
        return _status(rsp)

    # returns list of {'TopicArn':'arn'}
    @safe_sns
    def list_topics(self):
        sns_client = boto3.client('sns')
        rsp = sns_client.list_topics()
        print(rsp)
        return _status(rsp), rsp['Topics']

    # returns list of queue urls
    @safe_sqs
    def list_queues(self):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.list_queues()
        return _status(rsp), rsp['QueueUrls']

    # returns queue url
    @safe_sqs
    def get_queue_url(self, name, owner):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.get_queue_url(QueueName=name, QueueOwnerAWSAccountId=owner)
        return _status(rsp), rsp['QueuUrl']

    # returns a queue and its attributes (for existance check)
    @safe_sqs
    def get_queue(self, url):
        sqs = boto3.resource('sqs')
        queue = sqs.Queue(url)
        return _status(rsp), queue, queue.attributes

    # returns new topic arn
    @safe_sns
    def create_topic(self, topic_name):
        sns_client = boto3.client('sns')
        rsp = sns_client.create_topic(Name=topic_name)
        return _status(rsp), rsp['TopicArn']

    # returns queue url
    @safe_sqs
    def create_queue(self, queue_name):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.create_queue(QueueName=queue_name)
        return _status(rsp), rsp['QueueUrl']

    # returns status code
    @safe_sqs
    def purge_queue(self, queue):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.purge_queue(QueueUrl=queue)
        return _status(rsp)

    # returns status code
    @safe_sqs
    def delete_queue(self, queue):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.delete_queue(QueueUrl=queue)
        return _status(rsp)

    # returns array of {'ReceiptHandle': handle, 'Body': text}
    @safe_sqs
    def recv_message(self, queue):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.receive_message(QueueUrl=queue, MaxNumberOfMessages=1)
        if 'Messages' not in rsp:
            return 404, None
        msgs = []
        for rawmsg in rsp['Messages']:
            msgs.append((rawmsg['ReceiptHandle'], rawmsg['Body']))
        return _status(rsp), msgs

    # returns http status
    @safe_sqs
    def delete_message(self, queue, handle):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.delete_message(QueueUrl=queue, ReceiptHandle=handle)
        return _status(rsp)

    # returns num_messages, handles of skipped messages
    @safe_sqs
    def recv_and_process(self, handler, queue, max=20):
        sqs_client = boto3.client('sqs')
        rsp = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max)
        if 'Messages' not in rsp:
            return 0, []
        num_msg = 0
        non_del = []
        for rawmsg in rsp['Messages']:
            ret = handler(rawmsg['Body'])
            num_msg += 1
            if ret:
                sqs_queue.delete_message(rawmsg['ReceiptHandle'])
            else:
                non_del.append(rawmsg['ReceiptHandle'])
        return num_msg, non_del

    # returns http status
    @safe_sns
    def subscribe_queue(self, topic_arn, queue_arn):
        sns_client = boto3.client('sns')
        rsp = sns_client.subscribe(TopicArn=topic_arn, Protocol='sqs', Endpoint=queue_arn)
        return _status(rsp), rsp['SubscriptionArn'] if 'SubscriptionArn' in rsp else None

    # returns http status
    @safe_sns
    def unsubscribe_queue(self, subscription_arn):
        sns_client = boto3.client('sns')
        rsp = sns_client.unsubscribe(SubscriptionArn=subscription_arn)
        return _status(rsp)

    # returns a
    @safe_sns
    def list_subscriptions_by_topic(self, topic_arn):
        sns_client = boto3.client('sns')
        subs = []
        next = None
        while True:
            if next is None:
                rsp = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
            else:
                rsp = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn, NextToken=next)
            for sub in rsp['Subscriptions']:
                subs.append(sub)
            if 'NextToken' not in rsp:
                break
            next = subs['NextToken']
        return _status(rsp), subs

    @safe_sns
    def add_permission(self, topic_arn, label, account, permission):
        sns_client = boto3.client('sns')
        rsp = sns_client.add_permission(TopicArn=topic_arn, Label=label, AWSAccountId=account, ActionName=permission)
        return _status(rsp)

    @safe_sns
    def remove_permission(self, topic_arn, label):
        sns_client = boto3.client('sns')
        rsp = sns_client.add_permission(TopicArn=topic_arn, Label=label)
        return _status(rsp)
