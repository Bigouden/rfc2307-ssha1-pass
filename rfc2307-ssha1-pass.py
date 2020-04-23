#!/usr/bin/python3
#coding: utf-8

import os
import hashlib
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode

# Description
# Base64 encoded hash with salt
# userPassword: {SSHA}MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0
# Base64 decoded value
#     SHA1 Hash      Salt
# --------------------++++
# 123456789012345678901234

def makeSecret(password):
    res = False
    while not res:
        salt = os.urandom(8)
        h = hashlib.sha1(password.encode('utf-8'))
        h.update(salt)
        secret = "{SSHA}%s" % encode(h.digest() + salt).decode('utf-8')
        if '-' in secret:
            res = False
            continue
        if '_' in secret:
            res = False
            continue
        res = True
    return secret

def checkPassword(challenge_password, password):
    challenge_bytes = decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password.encode('utf-8'))
    hr.update(salt)
    return digest == hr.digest()

if __name__ == '__main__':
     challenge_password = makeSecret('true_password')
     print(challenge_password)
     print(checkPassword(challenge_password, 'true_password'))
     print(checkPassword(challenge_password, 'false_password'))
