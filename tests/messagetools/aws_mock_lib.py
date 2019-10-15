# aws mock data

import aws_mock_data


def mock_client(type):
    print('** my_client ** ' + type)
    if type == 'sqs':
        return mock_sqs_client
    if type == 'sns':
        return mock_sns_client
    assert type == 'sqs' or type == 'sns'


class mock_sqs_client():

    def __init__(self):
        self.called = 0

    def list_queues():
        print('** sqs list_queues **')
        # self.called += 1
        return aws_mock_data.list_queues_response_1

    def called_once(self):
        return self.called == 1


class mock_sns_client():

    def __init__(self):
        self.called = 0

    def list_topics():
        print('** sns list_topics **')
        # self.called += 1
        return aws_mock_data.list_topics_response_1

    def called_once(self):
        return self.called == 1
