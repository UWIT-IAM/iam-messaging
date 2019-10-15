
from messagetools.iam_message import crypt_init
from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message

import tests.test_settings as settings
import os


def test_crypt_decrypt():

    crypt_init(settings.IAM_CONF)

    sigkey = 'test-iamsig1'
    cryptkey = 'test-iamcrypt2'
    enc_msg = encode_message(settings.crypt_message, settings.crypt_context, cryptkey, sigkey)
    
    # save the encoded message for other tests
    print(enc_msg, file=open('/tmp/enc.txt', 'w'))

    dec_msg = decode_message(enc_msg)
    assert dec_msg['body'] == settings.crypt_message
    assert dec_msg['header']['messageContext'] == settings.crypt_context
