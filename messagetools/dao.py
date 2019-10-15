# iam-messaging implementation for non-django applications

import settings 

# from messagetools.mock.mock_http import MockHTTP
from messagetools.dao_implementation.aws import File as AWSFile
from messagetools.dao_implementation.aws import Live as AWSLive

class DAO_BASE(object):
             
    def __init__(self, conf):
        self._conf = conf
        if 'RUN_MODE' in conf:
            self._run_mode = conf['RUN_MODE']
        else:
            import settings
            self._run_mode = settings.RUN_MODE

    def _get_queue(self, queue_name):
        dao = self._getDAO()
        response = dao.get_queue(queue_name)
        return response

    def _get_all_topics(self):
        dao = self._getDAO()
        response = dao.get_all_topics()
        return response

    def _get_all_queues(self):
        dao = self._getDAO()
        response = dao.get_all_queues()
        return response

    def _create_topic(self, name):
        dao = self._getDAO()
        response = dao.create_topic(name)
        return response

    def _send_message(self, msg, context, cryptid, signid):
        dao = self._getDAO()
        response = dao.send_message(msg, context, cryptid, signid)
        return response

    def _create_queue(self, name):
        dao = self._getDAO()
        response = dao.create_queue(name)
        return response

    def _purge_queue(self, name):
        dao = self._getDAO()
        response = dao.purge_queue(name)
        return response

    def _delete_queue(self, name):
        dao = self._getDAO()
        response = dao.delete_queue(name)
        return response

    def _get_all_subscriptions_by_topic(self, topic):
        dao = self._getDAO()
        response = dao.get_all_subscriptions_by_topic(topic)
        return response

    def _create_subscription(self, topic_name, name):
        dao = self._getDAO()
        response = dao.create_subscription(topic_name, name)
        return response

    def _recv_message(self, queue_name):
        dao = self._getDAO()
        response = dao.recv_message(queue_name)
        return response

    def _recv_and_process(self, handler, queue_name, max=1):
        dao = self._getDAO()
        response = dao.recv_and_process(handler,queue_name, max)
        return response

    def _subscribe_queue(self, topic_name, queue_name):
        dao = self._getDAO()
        response = dao.subscribe_queue(topic_name, queue_name)
        return response

    def _add_permission(self, topic_name, label, account, permission):
        dao = self._getDAO()
        response = dao.add_permission(topic_name, label, account, permission)
        return response




class AWS_DAO(DAO_BASE):

    def create_topic(self, name):
        return self._create_topic(name)

    def send_message(self, msg, context, cryptid, signid):
        return self._send_message(msg, context, cryptid, signid)

    def get_queue(self, queue_name):
        return self._get_queue(queue_name)

    def get_all_queues(self):
        return self._get_all_queues()

    def get_all_topics(self):
        return self._get_all_topics()

    def create_queue(self, name):
        return self._create_queue(name)

    def purge_queue(self, name):
        return self._purge_queue(name)

    def delete_queue(self, name):
        return self._delete_queue(name)

    def recv_message(self, queue_name):
        return self._recv_message(queue_name)

    def recv_and_process(self, handler, queue_name,  max=1):
        return self._recv_and_process(handler,queue_name, max)

    def subscribe_queue(self, topic_name, queue_name):
        return self._subscribe_queue(topic_name, queue_name)

    def get_all_subscriptions_by_topic(self, topic):
        return self._get_all_subscriptions_by_topic(topic)

    def add_permission(self, topic_name, label, account, permission):
        return self._add_permission(topic_name, label, account, permission)

    def _getDAO(self):
        if self._run_mode=='Live':
            return AWSLive(self._conf)
        return AWSFile(self._conf)


