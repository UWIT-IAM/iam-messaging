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
from cryptography.exceptions import InvalidSignature

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
import logging

from messagetools.exceptions import CryptKeyException
from messagetools.exceptions import SigningCertException
from messagetools.exceptions import MessageException


# ----- global vars (to this module) ------------------

logger = logging.getLogger(__name__)

# decryption keys
_crypt_keys = {}

# public keys used for sig verify
_public_keys = {}

# private keys used for sig sign
_private_keys = {}

# ca certificate file for sig key fetch
_ca_file = None

#
# Accumulate header fields for signature
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


# test if str is 'simple'
_simple_allowed = set(string.ascii_letters + string.digits + '-')


def _if_simple(str):
    if set(str) <= _simple_allowed:
        return str
    raise MessageException('Invalid message header information', MessageException.invalid_header)

#
#  create a signed (maybe encrypted) iam message
#
#  msg: string
#  header:
#      contentType:    simple string (letters digits '-')
#      messageType:    simple string
#      sender:         string string
#      messageContext: string
#  cryptid: encryption key, None for no encryption
#  signid: signing key id


def encode_message(msg, header, cryptid, signid):

    iamHeader = {}
    iamHeader['version'] = 'UWIT-2'

    iamHeader['contentType'] = _if_simple(header['contentType'])
    iamHeader['messageType'] = _if_simple(header['messageType'])
    iamHeader['sender'] = _if_simple(header['sender'])
    iamHeader['messageId'] = str(uuid.uuid4())
    iamHeader['messageContext'] = base64.b64encode(header['messageContext'].encode('utf-8', 'ignore')).decode('utf-8', 'ignore')

    iamHeader['timestamp'] = datetime.datetime.utcnow().isoformat()
    if signid not in _private_keys:
        raise SigningCertException('Signing key not found: ' + signid)
    iamHeader['signingCertUrl'] = _private_keys[signid]['url']

    if cryptid is not None:
        if cryptid not in _crypt_keys:
            raise CryptKeyException('Encryption key not found: ' + cryptid)
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
    # print ('sigmsg:' + sigmsg.decode('utf-8'))

    key = _private_keys[signid]['key']
    pre = hashlib.sha256(sigmsg).digest()

    # some advise the use of 'PSS.MAX_LENGTH' for the salt length, but
    # I don't see how that works with other languages

    sig = key.sign(sigmsg, a_padding.PSS(mgf=a_padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    sig64 = base64.b64encode(sig).decode('utf-8', 'ignore')
    # print ('enc sig64 = ' + sig64)
    iamHeader['signature'] = sig64

    # debugging stuff
    # with open('sigmsg', 'w') as f:
    #    f.write(sigmsg.decode('utf-8'))
    # with open('sigsig', 'wb') as f:
    #    f.write(sig)

    body = {}
    body['Message'] = enctxt64

    iamMessage = {}
    iamMessage['header'] = iamHeader
    iamMessage['body'] = enctxt64

    m64 = base64.b64encode(json.dumps(iamMessage).encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
    return m64

#
#  receive a signed (maybe encrypted) iam message
#


def decode_message(b64msg):
    global _crypt_keys
    global _public_keys
    global _ca_file

    # get the message
    try:
        msgstr = base64.b64decode(b64msg).decode('utf-8', 'ignore')
        iam_message = json.loads(msgstr)
    except json.decoder.JSONDecodeError as e:
        logging.info('Not an iam message: invalid json')
        raise MessageException('Not an iam message: invalid json', MessageException.not_iam_message)

    if 'header' not in iam_message:
        logging.info('Not an iam message: no header')
        raise MessageException('Not an iam message: no header', MessageException.not_iam_message)
    iamHeader = iam_message['header']

    try:
        # check the version
        if iamHeader[u'version'] != 'UWIT-2':
            logging.error('unknown version: ' + iamHeader[u'version'])
            raise MessageException('Unknown message version: ' + iamHeader[u'version'], MessageException.bad_version)

        # fetch the signing cert if it's not cached
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
                    raise SigningCertException('Signers public key not found, url=%s,  status=%d' % (certurl, certdoc.status))
                logger.debug('got it')
                pem = certdoc.data
            else:
                raise SigningCertException('Invalid signers public key: ' + certurl)

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
        pubkey.verify(sig, sigmsg, a_padding.PSS(mgf=a_padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())

        # decrypt the message
        if 'keyId' in iamHeader:
            iv64 = iamHeader[u'iv']
            iv = base64.b64decode(iv64.encode('utf-8', 'ignore'))
            keyid = iamHeader[u'keyId']
            if keyid not in _crypt_keys:
                logger.error('key ' + keyid + ' not found')
                raise CryptKeyException('Decryption key not found: ' + keyid)
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

        iam_message[u'body'] = txt
        # context is b64 encoded
        try:
            iamHeader[u'messageContext'] = base64.b64decode(iamHeader[u'messageContext'].encode('utf-8', 'ignore')).decode('utf-8', 'ignore')
        except TypeError:
            logger.info('context not base64')
            iamHeader[u'messageContext'] = None
    except InvalidSignature as e:
        logger.error('signature verify fails')
        raise SignatureVerifyException(str(e))

    except KeyError as e:
        if 'AlarmName' in iam_message:
            logger.debug('alarm: ' + iam_message['AlarmName'])
            return iam_message

        logger.error('Unknown message key: ')
        raise MessageException('Message key: ' + str(e))

    return iam_message


def crypt_init(cfg):
    global _crypt_keys
    global _public_keys
    global _ca_file

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

    # are we verifying URLs (for the signing certs)
    if 'ca_file' in cfg:
        _ca_file = cfg['CA_FILE']
