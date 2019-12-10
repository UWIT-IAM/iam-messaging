#
# IAM AWS messaging mgement
#

# json classes
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
from messagetools.aws import AWS

import settings

#
# ---------------- gws_ce main --------------------------
#

# load configuration

parser = OptionParser()
parser.add_option('-o', '--operation', action='store', type='string', dest='operation',
                  help='cq=create_queue, ct=create_topic, sq=subscribe_queue, pq=purge_queue, dq=delete_queue,' \
                  'lq=list_queue(s), lt=list_topics, lqt=list_queues_for_topic, ltq=list_topics_for_queue ')
parser.add_option('-t', '--topic', action='store', type='string', dest='topic', help='topic')
parser.add_option('-q', '--queue', action='store', type='string', dest='queue', help='queue')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
parser.add_option('-a', '--account', action='store', type='string', dest='account', help='AWS account')
options, args = parser.parse_args()

if options.operation is None:
    print('operation must be entered')
    exit(1)


def _need_ext(name, typ):
    if name.find('arn:') >= 0:
        print('%s needs the %s extension name' % (options.operation, typ))
        exit(1)


def _need_full(name, typ):
    if name.find('arn:') < 0:
        print('%s needs the %s full name' % (options.operation, typ))
        exit(1)


crypt_init(settings.IAM_CONF)

logging.info("sws queue monitor starting.")

aws = AWS(settings.AWS_CONF)

if options.operation == 'lt':
    print('topic arns:')
    status, topics = aws.list_topics()
    for topic in topics:
        print(topic['TopicArn'])

if options.operation == 'lq':
    print('queue urls:')
    status, queues = aws.list_queues()
    for q in queues:
        print(q)

if options.operation == 'lqt':
    if options.topic is None:
        print('you must specify a topic')
        exit
    print('list queues for topic: ' + options.topic)
    _need_full(options.topic, 'topic')
    status, queues = aws.list_subscriptions_by_topic(options.topic)
    # print(queues)
    for queue in queues['ListSubscriptionsByTopicResponse']['ListSubscriptionsByTopicResult']['Subscriptions']:
        print(queue['Endpoint'])

if options.operation == 'ltq':
    if options.queue is None:
        print('you must specify a queue')
        exit
    print('list topics for queue ')
    _need_full(options.queue, 'queue')
    status, topics = aws.list_topics()
    for topic in topics['ListTopicsResponse']['ListTopicsResult']['Topics']:
        # print(topic['TopicArn'])
        status, queues = aws.list_subscriptions_by_topic(topic['TopicArn'])
        for queue in queues['ListSubscriptionsByTopicResponse']['ListSubscriptionsByTopicResult']['Subscriptions']:
            if queue['Endpoint'] == options.queue:
                print(topic['TopicArn'])

if options.operation == 'ct':
    print('creating topic: ' + options.topic)
    _need_ext(options.topic, 'topic')
    status, aws.create_topic(options.topic)

if options.operation == 'cq':
    print('creating queue: ' + options.queue)
    _need_ext(options.queue, 'queue')
    status, aws.create_queue(options.queue)

if options.operation == 'pq':
    print('purging queue: ' + options.queue)
    _need_ext(options.queue, 'queue')
    status, aws.purge_queue(options.queue)

if options.operation == 'dq':
    print('deleting queue: ' + options.queue)
    _need_ext(options.queue, 'queue')
    status, aws.delete_queue(options.queue)

if options.operation == 'sq':
    print('subscribing queue: ' + options.queue + ' to topic ' + options.topic)
    status, aws.subscribe_queue(options.topic, options.queue)

if options.operation == 'ps':
    print('permit subscribe: ' + options.account + ' to topic ' + options.topic)
    label = 'permit sub from ' + options.account
    status, aws.add_permission(options.topic, label, options.account, 'Subscribe')
