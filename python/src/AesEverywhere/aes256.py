# -*- coding: utf-8 -*-
#
# ===================================================================
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
# ===================================================================
"""
aes256.py
AES Everywhere - Cross Language Encryption Library https://github.com/mervick/aes-everywhere
(c) Andrey Izman <izmanw@gmail.com>
"""

import sys
import base64
from hashlib import md5
from Crypto import Random
from Crypto.Cipher import AES

__author__    = "Andrey Izman"
__email__     = "izmanw@gmail.com"
__copyright__ = "Copyright 2018-2019 Andrey Izman"
__license__   = "MIT"


class aes256:

    BLOCK_SIZE = 16
    KEY_LEN = 32
    IV_LEN = 16

    def encrypt(self, raw, passphrase):
        """
        Encrypt text with the passphrase
        @param raw: string Text to encrypt
        @param passphrase: string Passphrase
        @type raw: string
        @type passphrase: string
        @rtype: string
        """
        salt = Random.new().read(8)
        key, iv = self.__derive_key_and_iv(passphrase, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(b'Salted__' + salt + cipher.encrypt(self.__pkcs7_padding(raw)))

    def decrypt(self, enc, passphrase):
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
        key, iv = self.__derive_key_and_iv(passphrase, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self.__pkcs7_trimming(cipher.decrypt(ct[16:]))

    def __pkcs7_padding(self, s):
        """
        Padding to blocksize according to PKCS #7
        calculates the number of missing chars to BLOCK_SIZE and pads with
        ord(number of missing chars)
        @see: http://www.di-mgt.com.au/cryptopad.html
        @param s: string Text to pad
        @type s: string
        @rtype: string
        """
        py2 = sys.version_info[0] == 2
        s_len = len(s if py2 else s.encode('utf-8'))
        s = s + (self.BLOCK_SIZE - s_len % self.BLOCK_SIZE) * chr(self.BLOCK_SIZE - s_len % self.BLOCK_SIZE)
        return s if py2 else bytes(s, 'utf-8')

    def __pkcs7_trimming(self, s):
        """
        Trimming according to PKCS #7
        @param s: string Text to unpad
        @type s: string
        @rtype: string
        """
        if sys.version_info[0] == 2:
            return s[0:-ord(s[-1])]
        return s[0:-s[-1]]

    def __derive_key_and_iv(self, password, salt):
        """
        Derive key and iv
        @param password: string Password
        @param salt: string Salt
        @type password: string
        @type salt: string
        @rtype: string
        """
        d = d_i = b''
        while len(d) < self.KEY_LEN + self.IV_LEN:
            d_i = md5(d_i + password.encode('utf-8') + salt).digest()
            d += d_i
        return d[:self.KEY_LEN], d[self.KEY_LEN:self.KEY_LEN + self.IV_LEN]


if __name__ == '__main__':    #code to execute if called from command-line
    print(aes256().decrypt(aes256().encrypt("text", "pass"), "pass"))
