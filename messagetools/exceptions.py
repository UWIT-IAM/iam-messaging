# base class
class IamException(Exception):
    pass


class SignatureVerifyException(Exception):
    pass


class SigningCertException(IamException):
    pass


class CryptKeyException(IamException):
    pass


class AWSException(IamException):
    pass


class MessageException(IamException):
    invalid_header = 1
    not_iam_message = 2
    bad_version = 3

    def __init__(self, msg, code=0):
        super(MessageException, self).__init__(msg)
        self.code = code
