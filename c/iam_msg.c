/* ========================================================================
 * Copyright (c) 2013 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* tools for standard uw messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "aws_sns.h"
#include "aws_sqs.h"
#include "iam_msg.h"
#include "iam_crypt.h"

#include "cJSON.h"

char *snsHost = NULL;
char *snsArn = NULL;
char *snsKeyId = NULL;
char *snsKey = NULL;

char *sqsHost = NULL;
char *sqsKeyId = NULL;
char *sqsKey = NULL;
char *sqsUrl = NULL;

IamMessage *iam_newIamMessage() {
   IamMessage *msg = (IamMessage*) malloc(sizeof(IamMessage));
   memset(msg, 0, sizeof(IamMessage));
   return msg;
}
void iam_freeIamMessage(IamMessage *msg) {
  iam_free(msg->contentType);
  iam_free(msg->version);
  iam_free(msg->uuid);
  iam_free(msg->messageContext);
  iam_free(msg->messageType);
  iam_free(msg->messageId);
  iam_free(msg->timestamp);
  iam_free(msg->sender);
  iam_free(msg->message);
  iam_free(msg);
}


// send a version 1 message
int iam_msgSend(IamMessage *msg, char *cryptid, char *signid) {
   return iam_msgSendArn(msg, cryptid, signid, NULL, NULL);
}

int iam_msgSendArn(IamMessage *msg, char *cryptid, char *signid, char *snshost, char *snsarn) {

   char *iv = NULL;
   char *emsg = NULL;
   int ret;

   char *vers = "UWIT-1";
   if (!msg->timestamp) msg->timestamp = iam_timestampNow();
   char *ts = msg->timestamp;
   char *ct = msg->contentType;
   char *mt = msg->messageType;
   char *sndr = msg->sender;
   char *ctx = iam_dataToBase64(msg->messageContext, strlen(msg->messageContext));

   if (!ct) ct = "unknown";
   if (!mt) mt = "unknown";
   char *uuid = iam_uuid();

   // encrypt the message with the crypt key
   if (cryptid) {
      int r = iam_encryptText(cryptid, msg->message, strlen(msg->message), &emsg, &iv);
      if (r==0) syslog(LOG_ERR, "encrypt fails! id=%s", cryptid);
   } else {
      // printf("message will not be encrypted\n");
      emsg = iam_dataToBase64(msg->message, strlen(msg->message));
   }

   // sign it
   int sigtxtl = strlen(emsg) + 2048;
   char *sigtxt = (char*) malloc(sigtxtl);
   char *sigurl = iam_getSignUrl(signid);
   if (cryptid) sprintf(sigtxt, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", ct, iv, cryptid, ctx, uuid, mt, sndr, sigurl, ts, vers, emsg);
   else sprintf(sigtxt, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", ct, ctx, uuid, mt, sndr, sigurl, ts, vers, emsg);
   char *sig = iam_computeSignature(sigtxt, signid);
   
   cJSON *jhdr = cJSON_CreateObject();
   cJSON_AddStringToObject(jhdr, "version", "UWIT-1");
   cJSON_AddStringToObject(jhdr, "contentType", ct);
   cJSON_AddStringToObject(jhdr, "messageContext", ctx);
   cJSON_AddStringToObject(jhdr, "messageType", mt);
   cJSON_AddStringToObject(jhdr, "messageId", uuid);
   cJSON_AddStringToObject(jhdr, "sender", sndr);
   cJSON_AddStringToObject(jhdr, "timestamp", ts);
   cJSON_AddStringToObject(jhdr, "signature", sig);
   cJSON_AddStringToObject(jhdr, "signingCertUrl", sigurl);
   if (cryptid) {
      cJSON_AddStringToObject(jhdr, "keyId", cryptid);
      cJSON_AddStringToObject(jhdr, "iv", iv);
   }

   // cJSON *jbod = cJSON_CreateObject();
   // cJSON_AddStringToObject(jbod, "Message", emsg);

   cJSON *jmsg = cJSON_CreateObject();
   cJSON_AddItemToObject(jmsg, "header", jhdr);
   cJSON_AddStringToObject(jmsg, "body", emsg);

   char *out = cJSON_Print(jmsg); 
   cJSON_Delete(jmsg);

   iam_free(emsg);
   iam_free(ctx);
   iam_free(iv);
   iam_free(sigtxt);
   iam_free(sig);

   if (snshost==NULL) ret = sns_sendMessage("gws", out, strlen(out));
   else ret = sns_sendMessageArn("gws", out, strlen(out), snshost, snsarn);
   if (ret==200) {
      msg->messageId = uuid;
   } else { 
      syslog(LOG_ERR, "SNS send error: %d", ret);
      iam_free(uuid);
   }

   iam_free(out);
   return ret;
}

IamMessage *iam_msgRecv() {

   SQSMessage *msg = sqs_getMessage();
   if (!msg) return (NULL);
   if (!msg->messageId) {
      IamMessage *err = iam_newIamMessage();
      err->error = msg->verified;
      err->message = strdup(msg->message);   
      freeSQSMessage(msg);
      return (err);
   }
   IamMessage *ret = iam_msgParse(msg->message);
   sqs_deleteMessage(msg->handle);
   freeSQSMessage(msg);
   return (ret);
}

IamMessage *iam_msgParse(char *msg) {

   IamMessage *ret = iam_newIamMessage();

   cJSON *root = cJSON_Parse(msg);
   if (!root) {
      syslog(LOG_ERR, "iam_msg: bad json: %s", msg);
      return (NULL);
   }

   cJSON *hdr = cJSON_GetObjectItem(root, "header");

   char *vers = safeDupString(hdr, "version");
   char *ctx = safeGetString(hdr, "messageContext");
   char *mt = safeDupString(hdr, "messageType");
   char *uuid = safeDupString(hdr, "messageId");
   char *ct = safeDupString(hdr, "contentType");
   char *ts = safeDupString(hdr, "timestamp");
   char *sndr = safeDupString(hdr, "sender");
   char *iv = safeGetString(hdr, "iv");
   char *cryptid = safeGetString(hdr, "keyId");
   char *sig = safeGetString(hdr, "signature");
   char *sigurl = safeGetString(hdr, "signingCertUrl");
    
   // cJSON *body = cJSON_GetObjectItem(root, "Body");
   char *emsg = safeGetString(root, "body");

   // check the signature
   int sigtxtl = strlen(emsg) + 2048;
   char *sigtxt = (char*) malloc(sigtxtl);
   if (cryptid) sprintf(sigtxt, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", ct, iv, cryptid, ctx, uuid, mt, sndr, sigurl, ts, vers, emsg);
   else sprintf(sigtxt, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", ct, ctx, uuid, mt, sndr, sigurl, ts, vers, emsg);
   int v = iam_verifySignature(sigtxt, sig, sigurl);
   if (v!=1) {
      syslog(LOG_ERR, "msg verify fails, sender=%s, uuid=%s", sndr, uuid);
      return (NULL);
   }

   char *message;
   if (cryptid) {
      v = iam_decryptText(cryptid, emsg, &message, iv);
      if (v==0) syslog(LOG_ERR, "decrypt fails\n");
   } else {
      message = iam_base64ToText(emsg);
      // printf("message was not encrypted\n");
   }


   ret->version = vers;
   ret->uuid = uuid;
   ret->messageContext = iam_base64ToText(ctx);
   ret->messageType = mt;
   ret->messageId = strdup(uuid);
   ret->timestamp = ts;
   ret->contentType = ct;
   ret->sender = sndr;
   ret->message = message;
 
   iam_free(sigtxt);
   cJSON_Delete(root);
   
   return ret;
}

int iam_msgInit(char *cfgfile) {
   int i;
   char *id;
   char *url;
   char *keyfile;
   char *k64;

   iam_crypt_init();

   char *cfgjs = iam_getFile(cfgfile);
   if (!cfgjs) return (0);
   cJSON *cfg = cJSON_Parse(cfgjs);
   if (!cfg) {
      syslog(LOG_ERR, "Invalid json in config file: %s", cfgfile);
      return (0);
   }

   char *s = safeGetString(cfg, "verbose");
   if (s) iamVerbose = atoi(s);

   char *slog = safeGetString(cfg, "syslog_facility");
   char *snam = safeDupString(cfg, "syslog_name");
   if (!snam) snam = "iam_msg";
   if (slog) {
      unsigned int l = LOG_SYSLOG;
      if (!strcmp(slog, "local0")) l = LOG_LOCAL0;
      if (!strcmp(slog, "local1")) l = LOG_LOCAL1;
      if (!strcmp(slog, "local2")) l = LOG_LOCAL2;
      if (!strcmp(slog, "local3")) l = LOG_LOCAL3;
      if (!strcmp(slog, "local4")) l = LOG_LOCAL4;
      if (!strcmp(slog, "local5")) l = LOG_LOCAL5;
      if (!strcmp(slog, "local6")) l = LOG_LOCAL6;
      if (!strcmp(slog, "local7")) l = LOG_LOCAL7;
      openlog(snam, LOG_PID, l);
      iamSyslog = 1;
   }
   if (iamSyslog) syslog(LOG_INFO, "%s starting", snam);

   cJSON *aws = cJSON_GetObjectItem(cfg, "aws");
   if (!aws) {
      if (iamSyslog) syslog(LOG_ERR, "No aws entry in config!");
      return (0);
   }
   snsHost = safeDupString(aws, "snsHost");
   snsArn = safeDupString(aws, "snsArn");
   snsKeyId = safeDupString(aws, "snsKeyId");
   snsKey = safeDupString(aws, "snsKey");

   sqsKeyId = safeDupString(aws, "sqsKeyId");
   sqsKey = safeDupString(aws, "sqsKey");
   sqsUrl = safeDupString(aws, "sqsUrl");

   // certs
   cJSON *crts = cJSON_GetObjectItem(cfg, "certs");
   if (crts) {
      int ncrts = cJSON_GetArraySize(crts);
      for (i=0 ; i<ncrts ; i++) {
        cJSON *crt = cJSON_GetArrayItem(crts, i);
        id = safeDupString(crt, "id");
        url = safeDupString(crt, "url");
        keyfile = safeDupString(crt, "keyfile");
        if (url) iam_setPubKey(id, url);
        if (keyfile) iam_setPvtKey(id, keyfile);
      }
   }

   // cryption keys
   cJSON *crypts = cJSON_GetObjectItem(cfg, "crypts");
   if (crypts) {
      int ncrypts = cJSON_GetArraySize(crypts);
      for (i=0 ; i<ncrypts ; i++) {
        cJSON *crypt = cJSON_GetArrayItem(crypts, i);
        id = safeDupString(crypt, "id");
        k64 = safeDupString(crypt, "key");
        iam_addCryptkey(id, k64);
      }
   }

   cJSON_Delete(cfg);
   iam_free(cfgjs);

   if (snsHost) sns_init(snsHost, snsArn, snsKey, snsKeyId);
   if (sqsUrl) sqs_init(sqsUrl, sqsKey, sqsKeyId);

   return (1);
}