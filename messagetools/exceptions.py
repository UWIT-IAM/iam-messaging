class SignatureVerifyException(Exception):
    pass

class SigningCertException(Exception):
    def __init__(self, url, status=0):
        self.url = url
        self.status = status

    def __str__(self):
        return ("Error fetching certificate from %s.  Status: %s" %
                (self.url, self.status))

class CryptKeyException(Exception):
    def __init__(self, keyid, msg):
        self.keyid = keyid
        self.msg = msg

    def __str__(self):
        return ("Crypt key error for key %s: %s" % (self.keyid, self.msg))

class TopicNotFoundException(Exception):
    def __init__(self, arn, msg):
        self.arn = arn
        self.msg = msg

    def __str__(self):
        return ("The topic arn '%s' was not found: %s" % (self.arn, self.msg))

class QueueNotFoundException(Exception):
    def __init__(self, msg=None):
        self.msg = '' if msg is None else msg

    def __str__(self):
        return (self.msg)

class ClientException(Exception):
    def __init__(self, msg):
        self.msg = '' if msg is None else msg

    def __str__(self):
        return (self.msg)

