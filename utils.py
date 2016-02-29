import re
import os
import logging
import random
import string
import hashlib
import hmac
from string import ascii_letters
import json
from passlib.hash import pbkdf2_sha256
import httplib2
from urllib import urlencode

# --- HASH COOKIES ---

SECRET = 'SUPER_SECRET_KEY'

def hash_str(val):
    return hmac.new(SECRET, val).hexdigest()

def make_secure_val(val):
    return "%s|%s" % (val, hash_str(val))

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if make_secure_val(val) == secure_val:
        return val


# --- VERIFY USER INPUT ---

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^(?=.*?\d)(?=.*?[A-Z])(?=.*?[a-z])[A-Za-z0-9_-]{8,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def valid_verify(value, verify):
    if value==verify:
        return True

TITLE_RE = re.compile(r"^.{1,78}$")
def valid_title(title):
    return TITLE_RE.match(title)

BODY_RE = re.compile(r"^(.|\n){1,20000}$")
def valid_body(body):
    return BODY_RE.match(body)

SUBJECT_RE = re.compile(r"^.{1,78}$")
def valid_subject(subject):
    return SUBJECT_RE.match(subject)

CONTENT_RE = re.compile(r"^(.|\n){1,1000}$")
def valid_content(content):
    return CONTENT_RE.match(content)

def valid_captcha(input_captcha):
    url = 'https://www.google.com/recaptcha/api/siteverify'
    h = httplib2.Http()
    data = dict(secret="YOUR_RECAPTCHA_SECRET_KEY", 
                response=input_captcha)
    resp, content = h.request(url, 'POST', urlencode(data))
    logging.error(resp)
    logging.error(json.loads(content)['success'])
    if not resp['status'] == '200':
        return False
    if json.loads(content)['success'] == True:
        return True
    else:
        return False

# --- HASH AND SALT PASSWORDS ---

# Generate secure password_hash for storing in DB and 
# verify pw from login.

class PWHandlerPDKDF2(object):
    """Make and verify secure PW hashes for storing in a Database.
    Cryptographic hash algorithm: sha256.
    Key stretching algorithm: none! -- NOT SECURE --

    Methods:
    make_salt -- Return random salt
    make_pw_hash -- Return a secure PW-hash. pw_hash = "salt,hash_value".
    valid_pw -- Return True if PW is valid, otherwise False
    """

    def make_salt():
        return os.urandom(64).encode('hex')

    def make_pw_hash(pw, salt = None):
        if not salt:
            salt = make_salt()
        h = hmac.new(salt, pw, hashlib.sha256).hexdigest()
        return '%s,%s' % (salt, h)

    def valid_pw(password, pw_hash):
        salt = pw_hash.split(',')[0]
        return pw_hash == make_pw_hash(password, salt)
        #pw_hash is safed in the database. pw_hash = "salt,hash_value".  



class PWHandlerPDKDF2(object):
    """Make and verify secure PW hashes for storing in a Database.
    Cryptographic hash algorithm: sha256.
    Key stretching algorithm: PDKDF2
    Third party library: passlib (https://pythonhosted.org/passlib)

    Methods:
    make_pw_hash -- Return a secure PW-hash.
    valid_pw -- Return True if PW is valid, otherwise False
    """

    def make_pw_hash(self, pw):
        h = pbkdf2_sha256.encrypt(pw, rounds=200000, salt_size=16)
        return h

    def valid_pw(self, password, pw_hash):
        try:
            return pbkdf2_sha256.verify(password, pw_hash)
        except ValueError:
            return False

