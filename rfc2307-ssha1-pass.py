#!/usr/bin/python3
#coding: utf-8

import hashlib
import hmac
import secrets
from base64 import b64encode, b64decode

def makeSecret(cleartext):
    h = hashlib.sha1(cleartext.encode('utf-8'))
    salt = secrets.token_bytes(8)
    h.update(salt)
    return "{SSHA}%s" % b64encode(h.digest() + salt).decode('utf-8')

def checkPassword(challenge_password, password):
    challenge_bytes = b64decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password.encode('utf-8'))
    hr.update(salt)
    return hmac.compare_digest(digest, hr.digest())

if __name__ == '__main__':
    challenge_password = makeSecret('true_password')
    print(challenge_password)
    print(checkPassword(challenge_password, 'true_password'))
    print(checkPassword(challenge_password, 'false_password'))
