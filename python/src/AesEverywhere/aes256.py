# -*- coding: utf-8 -*-
# aes256.py
# This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
#
# This is an implementation of the AES algorithm, specifically CBC mode,
# with 256 bits key length and PKCS7 padding.
#
# Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import sys
import base64
from hashlib import md5
from Cryptodome import Random
from Cryptodome.Cipher import AES

__author__    = "Andrey Izman"
__email__     = "izmanw@gmail.com"
__copyright__ = "Copyright 2018-2019 Andrey Izman"
__license__   = "MIT"



py2 = sys.version_info[0] == 2

BLOCK_SIZE = 16
KEY_LEN = 32
IV_LEN = 16

def encrypt(raw, passphrase):
    """
    Encrypt text with the passphrase
    @param raw: string Text to encrypt
    @param passphrase: string Passphrase
    @type raw: string
    @type passphrase: string
    @rtype: string
    """
    salt = Random.new().read(8)
    key, iv = __derive_key_and_iv(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b'Salted__' + salt + cipher.encrypt(__pkcs7_padding(raw)))

def decrypt(enc, passphrase):
    """
    Decrypt encrypted text with the passphrase
    @param enc: string Text to decrypt
    @param passphrase: string Passphrase
    @type enc: string
    @type passphrase: string
    @rtype: string
    """
    ct = base64.b64decode(enc)
    salted = ct[:8]
    if salted != b'Salted__':
        return ""
    salt = ct[8:16]
    key, iv = __derive_key_and_iv(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return __pkcs7_trimming(cipher.decrypt(ct[16:]))

def __pkcs7_padding(s):
    """
    Padding to blocksize according to PKCS #7
    calculates the number of missing chars to BLOCK_SIZE and pads with
    ord(number of missing chars)
    @see: http://www.di-mgt.com.au/cryptopad.html
    @param s: string Text to pad
    @type s: string
    @rtype: string
    """
    s_len = len(s if py2 else s.encode('utf-8'))
    s = s + (BLOCK_SIZE - s_len % BLOCK_SIZE) * chr(BLOCK_SIZE - s_len % BLOCK_SIZE)
    return s if py2 else bytes(s, 'utf-8')

def __pkcs7_trimming(s):
    """
    Trimming according to PKCS #7
    @param s: string Text to unpad
    @type s: string
    @rtype: string
    """
    if sys.version_info[0] == 2:
        return s[0:-ord(s[-1])]
    return s[0:-s[-1]]

def __derive_key_and_iv(password, salt):
    """
    Derive key and iv
    @param password: string Password
    @param salt: string Salt
    @type password: string
    @type salt: string
    @rtype: string
    """
    d = d_i = b''
    enc_pass = password if py2 else password.encode('utf-8')
    while len(d) < KEY_LEN + IV_LEN:
        d_i = md5(d_i + enc_pass + salt).digest()
        d += d_i
    return d[:KEY_LEN], d[KEY_LEN:KEY_LEN + IV_LEN]


if __name__ == '__main__':    #code to execute if called from command-line
    print(decrypt(encrypt("text", "pass"), "pass"))
