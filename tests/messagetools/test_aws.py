# aws.py tester

from mock import patch

from messagetools.aws import AWS
import boto3
import tests.test_settings as settings
from aws_mock_lib import mock_client
import aws_mock_data


class TestAWS():
    aws = AWS(settings.AWS_CONF)

    @patch('boto3.client', side_effect=mock_client)
    def test_list_queues(self, mock_client):
        status, list = self.aws.list_queues()
        assert mock_client.called_once()
        assert status == 200
        assert list[0] == aws_mock_data.list_queue_url_1

    @patch('boto3.client', side_effect=mock_client)
    def test_list_topics(self, mock_client):
        status, list = self.aws.list_topics()
        assert mock_client.called_once()
        assert status == 200
        assert list[0]['TopicArn'] in aws_mock_data.list_topics_arns
        assert list[1]['TopicArn'] in aws_mock_data.list_topics_arns
