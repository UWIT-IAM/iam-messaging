# settings config for tests


import os
settings_path = os.path.dirname(os.path.abspath(__file__))
print(settings_path)


CA_FILE = '../certs/test-ca.crt'


AWS_CONF = {
    'SNS_HOST':  'mock.xxx-1.amazonaws.com',
    'SNS_ARN':  'mock.arn:aws:sns::999909864246:iam-gws-activity-dev',
    'SNS_KEYID': 'mock-keyid',
    'SNS_KEY':   'mock-key',
    'SQS_KEYID': 'mock-keyid',
    'SQS_KEY':   'mock-key',
    'SQS_QUEUE':  'gws-sync-12.fifo',
    'REGION': 'us-west-2',
    'DEFAULT_KEYID': 'mock-keyid',
    'DEFAULT_KEY':   'mock-key',
}

AZURE_CONF = {
    'NAMESPACE':  'xxxx',
    'ACCESS_KEY_NAME':  'xxxx',
    'ACCESS_KEY_VALUE':  'xxxx',
    'TOPIC_NAME':  'xxxx',
    'SUBSCRIPTION_NAME': 'xxxx',
}


IAM_CONF = {
    'CERTS':  [
        {
            "ID": "test-iamsig1",
            "URL": "file:%s/certs/test-2048.crt" % settings_path,
            "KEYFILE": "%s/certs/test-2048.key" % settings_path
        }
    ],
    'CRYPTS': [
     {"ID": "test-iamcrypt1",
      "KEY": "YjZmNTM5ZTE3M2QzNGZjOWExOWZhNGRlNTEyNWI0NTgK"
      },
     {"ID": "test-iamcrypt2",
      "KEY": "MDYyMzVmMTQ0ZmIyNDBhOGFhMTM0M2M4YTZkZjZlYWI="
      }
     ],
    'CA_FILE': "../certs/test-ca.crt",
    'SENDER': 'messaging tester'
}

LOGGING = {
    'version': 1,
    'formatters': {
        'plain': {
            'format': '%(message)s'
        },
        'syslog': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'class': 'logging.StreamHandler',
            'level': 'WARN',
            'stream': 'ext://sys.stdout',
            'formatter': 'plain',
        },
        'syslog': {
            'class': 'logging.handlers.SysLogHandler',
            'level': 'WARN',
            'formatter': 'syslog',
            'facility': 'LOG_LOCAL7'
        }
    },
    'root': {
        'level': 'WARN',
        'handlers': ['default'],
    },
    'suds': {
        'level': 'WARN',
        'handlers': ['default']
    },
}

crypt_header = {
    'contentType':'plain',
    'messageType':'test-0',
    'sender':'fox',
    'messageContext':'Hello, world.'
}
crypt_message = 'Every good boy and girl does fine.'

