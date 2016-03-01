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
# 

# crypto class covers for openssl
from M2Crypto import BIO, RSA, EVP, X509

import json
import uuid
import datetime
import dateutil.parser
import base64
import string
import time
import re
import os.path
import sys
import signal
import importlib

import urllib3

import threading

from exceptions import SignatureVerifyException
from exceptions import CryptKeyException
from exceptions import SigningCertException

# ----- global vars (to this module) ------------------

# decryption keys
_crypt_keys = {}

# public keys used for sig verify
_public_keys = {}

# private keys used for sig sign
_private_keys = {}

# ca certificate file
_ca_file = None

import logging
logger = None

#
# -------------------------------------
#

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
    iamHeader['version'] = 'UWIT-1'
    iamHeader['messageType'] = 'iam-test'
    u = uuid.uuid4()
    iamHeader['messageId'] = str(u)
    iamHeader['messageContext'] = base64.b64encode(context)
    iamHeader['sender'] = 'iam-msg'

    iamHeader['timestamp'] = datetime.datetime.utcnow().isoformat()
    if signid not in _private_keys:
        raise SigningCertException(keyid=signid, msg='not found')
    iamHeader['signingCertUrl'] = _private_keys[signid]['url']

    if cryptid!=None:
        if cryptid not in _crypt_keys:
            raise CryptKeyException(keyid=cryptid, msg='not found')
        iamHeader['keyId'] = cryptid
        iv = os.urandom(16)
        iamHeader['iv'] = base64.b64encode(iv)
        cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=_crypt_keys[cryptid], iv=iv, op=1)
        txt = cipher.update(msg) + cipher.final()
        enctxt64 = base64.b64encode(txt)
    else:
        enctxt64 = base64.b64encode(msg)
    
    # gen the signature
    sigmsg = _build_sig_msg(iamHeader, enctxt64)

    key = _private_keys[signid]['key']
    key.reset_context(md='sha1')
    key.sign_init()
    key.sign_update(sigmsg)
    sig = key.sign_final()
    sig64 = base64.b64encode(sig)
    iamHeader['signature'] = sig64

    body = {}
    body['Message'] = enctxt64
  
    iamMessage = {}
    iamMessage['header'] = iamHeader
    iamMessage['body'] = enctxt64

    m64 = base64.b64encode(json.dumps(iamMessage))
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
        msgstr = base64.b64decode(b64msg).encode('utf8','ignore')
    except TypeError:
        logger.info( 'Not an IAM message: not base64')
        return None
    iam_message = json.loads(msgstr)


    if 'header' not in iam_message: 
        logger.info('not an iam message')
        return None
    iamHeader = iam_message['header']

    try:
      # check the version
      if iamHeader[u'version'] != 'UWIT-1':
          logger.error('unknown version: ' + iamHeader[u'version'])
          return None

      # the signing cert should be cached most of the time
      certurl = iamHeader[u'signingCertUrl']
      if not certurl in _public_keys:
          logger.info('Fetching signing cert: ' + certurl)
          pem = ''

          if certurl.startswith('file:'):
              with open(certurl[5:], 'r') as f:
                  pem = f.read()

          elif certurl.startswith('http'):
              # not looking at ca file till we know how
              conn = urllib3.connection_from_url(certurl, ssl_version=ssl.PROTOCOL_TLSv1)
              certdoc = conn.request('GET', certurl)
              if certdoc.status != 200:
                  logger.error('sws cert get failed: ' + certdoc.status)
                  raise SigningCertException(url=certurl, status=certdoc.status)
              logger.debug('got it')
              pem = certdoc.data
          else:
              raise SigningCertException(url=certurl, status=-1)

          x509 = X509.load_cert_string(pem)
          key = x509.get_pubkey()
          _public_keys[certurl] = key

      enctxt64 = iam_message[u'body']

      # check the signature

      sigmsg = _build_sig_msg(iamHeader, enctxt64)
      sig = base64.b64decode(iamHeader[u'signature'])
      pubkey = _public_keys[certurl]
      pubkey.reset_context(md='sha1')
      pubkey.verify_init()
      pubkey.verify_update(sigmsg)
      if pubkey.verify_final(sig)!=1:
          raise SignatureVerifyException()

      # decrypt the message
      if 'keyId' in iamHeader:
          iv64 = iamHeader[u'iv']
          iv = base64.b64decode(iv64)
          keyid = iamHeader[u'keyId']
          if not keyid in _crypt_keys:
              logger.error('key ' + keyid + ' not found')
              raise CryptKeyException(keyid=keyid, msg='not found')
          key = _crypt_keys[keyid]
 
          enctxt =  base64.b64decode(enctxt64)
          cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=0)
          txt = cipher.update(enctxt) + cipher.final()
      else:
          txt = base64.b64decode(enctxt64)

      txt = filter(lambda x: x in string.printable, txt)
      iam_message[u'body'] = txt
      # un-base64 the context
      try:
          iamHeader[u'messageContext'] = base64.b64decode(iamHeader[u'messageContext'])
      except TypeError:
          logger.info( 'context not base64')
          return None
    except KeyError:
        if 'AlarmName' in iam_message:
            logger.debug('alarm: ' + iam_message['AlarmName'])
            return iam_message

        logger.error('Unknown message key: ' )
        return None

    return iam_message


def crypt_init(cfg):
    global _crypt_keys
    global _public_keys
    global _ca_file
    global logger

    logger = logging.getLogger(__name__)

    # load the signing keys
    certs = cfg['CERTS']
    for c in certs:
        id = c['ID']
        crt = {}
        crt['url'] = c['URL']
        crt['key'] = EVP.load_key(c['KEYFILE'])
        _private_keys[id] = crt


    # load the cryption key
    keys = cfg['CRYPTS']
    for k in keys:
        id = k['ID']
        k64 = k['KEY']
        logger.debug('adding crypt key ' + id)
        kbin = base64.b64decode(k64)
        _crypt_keys[id] = kbin

    # are we verifying certs ( just for the signing cert )
    if 'CA_FILE' in cfg:
        _ca_file = cfg['CA_FILE']
        
    # skip ssl warning for older pythons
    if sys.hexversion < 0x02070900:
        logger.info('Ignoring urllib3 ssl security warning: https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning')
        # urllib3.disable_warnings()
