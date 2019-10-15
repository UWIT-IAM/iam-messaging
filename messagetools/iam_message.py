#  ========================================================================
#  Copyright (c) 2015 The University of Washington
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  ========================================================================
#

#
# IAM messaging tools - encryption and signature methods
#

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as a_padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import hashlib
import json
import uuid
import datetime
import base64
import string
import time
import re
import os.path
from sys import exit
import signal
import importlib

import urllib3
import threading
import logging

from messagetools.exceptions import SignatureVerifyException
from messagetools.exceptions import CryptKeyException
from messagetools.exceptions import SigningCertException
from messagetools.exceptions import TopicNotFoundException
from messagetools.exceptions import QueueNotFoundException
from messagetools.exceptions import ClientException


# ----- global vars (to this module) ------------------

# decryption keys
_crypt_keys = {}

# public keys used for sig verify
_public_keys = {}

# private keys used for sig sign
_private_keys = {}

# ca certificate file
_ca_file = None

# message sender
_sender = 'iam'

logger = logging.getLogger(__name__)

#
# accumulate header fields for signature
#


def _build_sig_msg(header, txt):
    sigmsg = header[u'contentType'] + '\n'
    if 'keyId' in header:
        sigmsg = sigmsg + header[u'iv'] + '\n' + header[u'keyId'] + '\n'
    sigmsg = sigmsg + header[u'messageContext'] + '\n' + header[u'messageId'] + '\n' + \
        header[u'messageType'] + '\n' + header[u'sender'] + '\n' + \
        header[u'signingCertUrl'] + '\n' + header[u'timestamp'] + '\n' + header[u'version'] + '\n' + \
        txt + '\n'
    return sigmsg.encode('ascii')

#
#  create a signed (and encrypted) iam message
#
#  msg is anything
#  context is string


def encode_message(msg, context, cryptid, signid):

    iamHeader = {}
    iamHeader['contentType'] = 'json'
    iamHeader['version'] = 'UWIT-2'
    iamHeader['messageType'] = 'iam-test'
    u = uuid.uuid4()
    iamHeader['messageId'] = str(u)
    iamHeader['messageContext'] = base64.b64encode(context.encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
    iamHeader['sender'] = _sender

    iamHeader['timestamp'] = datetime.datetime.utcnow().isoformat()
    if signid not in _private_keys:
        raise SigningCertException(keyid=signid, msg='not found')
    iamHeader['signingCertUrl'] = _private_keys[signid]['url']

    if cryptid is not None:
        if cryptid not in _crypt_keys:
            raise CryptKeyException(keyid=cryptid, msg='not found')
        iamHeader['keyId'] = cryptid
        iv = os.urandom(16)
        iamHeader['iv'] = base64.b64encode(iv).decode('utf-8', 'ignore')
        padder = padding.PKCS7(128).padder()
        pmsg = padder.update(msg.encode('utf-8', 'ignore')) + padder.finalize()
        key = _crypt_keys[cryptid]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        txt = enc.update(pmsg) + enc.finalize()
        enctxt64 = base64.b64encode(txt).decode('utf-8', 'ignore')
        # print (enctxt64)
    else:
        enctxt64 = base64.b64encode(msg.encode('utf-8', 'ignore')).decode('utf-8', 'ignore')

    # gen the signature
    sigmsg = _build_sig_msg(iamHeader, enctxt64)
    # print (sigmsg)

    key = _private_keys[signid]['key']
    pre = hashlib.sha256(sigmsg).digest()
    sig = key.sign(pre, a_padding.PSS(mgf=a_padding.MGF1(hashes.SHA256()), salt_length=a_padding.PSS.MAX_LENGTH), hashes.SHA256())
    sig64 = base64.b64encode(sig).decode('utf-8', 'ignore')
    # print ('enc sig64 = ' + sig64)
    iamHeader['signature'] = sig64

    body = {}
    body['Message'] = enctxt64

    iamMessage = {}
    iamMessage['header'] = iamHeader
    iamMessage['body'] = enctxt64

    m64 = base64.b64encode(json.dumps(iamMessage).encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
    return m64

#
#  receive a signed (and encrypted) iam message
#


def decode_message(b64msg):
    global _crypt_keys
    global _public_keys
    global _ca_file

    # get the iam message
    try:
        msgstr = base64.b64decode(b64msg).decode('utf-8', 'ignore')
        iam_message = json.loads(msgstr)
    except json.decoder.JSONDecodeError as e:
        logging.info('invalid json.  Not an iam message')
        return None

    if 'header' not in iam_message:
        logging.info('not an iam message')
        return None
    iamHeader = iam_message['header']

    try:
        # check the version
        if iamHeader[u'version'] != 'UWIT-2':
            logging.error('unknown version: ' + iamHeader[u'version'])
            return None

        # the signing cert should be cached most of the time
        certurl = iamHeader[u'signingCertUrl']
        if certurl not in _public_keys:
            logging.info('Fetching signing cert: ' + certurl)
            pem = ''

            if certurl.startswith('file:'):
                with open(certurl[5:], 'r') as f:
                    pem = f.read()

            elif certurl.startswith('http'):
                if _ca_file is not None:
                    http = urllib3.PoolManager(
                        cert_reqs='CERT_REQUIRED',  # Force certificate check.
                        ca_certs=_ca_file,
                    )
                else:
                    http = urllib3.PoolManager()
                certdoc = http.request('GET', certurl)
                if certdoc.status != 200:
                    logger.error('sws cert get failed: ' + certdoc.status)
                    raise SigningCertException(url=certurl, status=certdoc.status)
                logger.debug('got it')
                pem = certdoc.data
            else:
                raise SigningCertException(url=certurl, status=-1)

            crt = x509.load_pem_x509_certificate(pem.encode('utf-8', 'ignore'), default_backend())
            key = crt.public_key()
            _public_keys[certurl] = key

        enctxt64 = iam_message[u'body']
        # print (enctxt64)

        # check the signature

        sigmsg = _build_sig_msg(iamHeader, enctxt64)
        pre = hashlib.sha256(sigmsg).digest()
        # print('dec sig = ' + iamHeader[u'signature'])
        sig = base64.b64decode(iamHeader[u'signature'].encode('utf-8', 'ignore'))
        pubkey = _public_keys[certurl]
        pubkey.verify(sig, pre, a_padding.PSS(mgf=a_padding.MGF1(hashes.SHA256()), salt_length=a_padding.PSS.MAX_LENGTH), hashes.SHA256())

        # decrypt the message
        if 'keyId' in iamHeader:
            iv64 = iamHeader[u'iv']
            iv = base64.b64decode(iv64.encode('utf-8', 'ignore'))
            keyid = iamHeader[u'keyId']
            if keyid not in _crypt_keys:
                logger.error('key ' + keyid + ' not found')
                raise CryptKeyException(keyid=keyid, msg='not found')
            key = _crypt_keys[keyid]

            enctxt = base64.b64decode(enctxt64.encode('utf-8', 'ignore'))
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec = cipher.decryptor()
            ptxt = dec.update(enctxt) + dec.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            txt = unpadder.update(ptxt) + unpadder.finalize()
        else:
            txt = base64.b64decode(enctxt64.encode('utf-8', 'ignore'))

        txt = txt.decode('utf-8', 'ignore')

        # print ('in[%d %s]'%(len(txt),txt))
        # _txt = list(filter(lambda x: x in string.printable, txt))
        # print ('out[%s]'%(_txt))
        iam_message[u'body'] = txt
        # un-base64 the context
        try:
            iamHeader[u'messageContext'] = base64.b64decode(iamHeader[u'messageContext'].encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
        except TypeError:
            logger.info('context not base64')
            return None
    except KeyError:
        if 'AlarmName' in iam_message:
            logger.debug('alarm: ' + iam_message['AlarmName'])
            return iam_message

        logger.error('Unknown message key: ')
        return None

    return iam_message


def crypt_init(cfg):
    global _crypt_keys
    global _public_keys
    global _ca_file
    global _sender

    # load the signing keys
    certs = cfg['CERTS']
    for c in certs:
        id = c['ID']
        crt = {}
        crt['url'] = c['URL']
        # crt['key'] = EVP.load_key(c['KEYFILE'])
        with open(c['KEYFILE'], "rb") as key_file:
            crt['key'] = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        _private_keys[id] = crt

    # load the cryption key
    keys = cfg['CRYPTS']
    for k in keys:
        id = k['ID']
        k64 = k['KEY']
        logger.debug('adding crypt key ' + id)
        kbin = base64.b64decode(k64.encode('utf-8', 'ignore'))
        _crypt_keys[id] = kbin

    # are we verifying certs ( just for the signing cert )
    if 'ca_file' in cfg:
        _ca_file = cfg['CA_FILE']

    # default message sender
    _sender = cfg['SENDER']
