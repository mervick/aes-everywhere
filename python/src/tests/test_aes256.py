# -*- coding: utf-8 -*-

import sys
from AesEverywhere import aes256

try:
    if sys.version_info < (2, 7):
        import unittest2
    else:
        raise ImportError()
except ImportError:
    import unittest


py2 = sys.version_info[0] == 2
FAIL = "Invalid decryption"

def u(str):
    return str.decode('utf-8').encode('utf-8') if py2 else str.encode('utf-8')


class TestAes256(unittest.TestCase):

    def test_decrypt1(self):
        text = aes256.decrypt("U2FsdGVkX1+Z9xSlpZGuO2zo51XUtsCGZPs8bKQ/jYg=", "pass")
        self.assertEqual(text, u("test"), FAIL)

    def test_decrypt2(self):
        text = aes256.decrypt("U2FsdGVkX1+8b3WpGTbZHtd2T9PNQ+N7GqebGaOV3cI=", "Data 😄 текст")
        self.assertEqual(text, u("test"), FAIL)

    def test_decrypt3(self):
        text = aes256.decrypt("U2FsdGVkX18Kp+T3M9VajicIO9WGQQuAlMscLGiTnVyHRj2jHObWshzJXQ6RpJtW", "pass")
        self.assertEqual(text, u("Data 😄 текст"), FAIL)

    def test_decrypt4(self):
        text = aes256.decrypt("U2FsdGVkX1/O7iqht/fnrFdjn1RtYU7S+DD0dbQHB6N/k+CjzowfC2B21QRG24Gv", "Data 😄 текст")
        self.assertEqual(text, u("Data 😄 текст"), FAIL)

    def test_encrypt_decrypt1(self):
        text = "Test! @#$%^&*"
        passw = "pass"
        enc = aes256.encrypt(text, passw)
        dec = aes256.decrypt(enc, passw)
        self.assertEqual(u(text), dec, FAIL)

    def test_encrypt_decrypt2(self):
        text = "Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺"
        passw = "pass"
        enc = aes256.encrypt(text, passw)
        dec = aes256.decrypt(enc, passw)
        self.assertEqual(u(text), dec, FAIL)

    def test_encrypt_decrypt3(self):
        text = "Test! @#$%^&*( 😆😵🤡👌 哈罗 こんにちわ Акїў 😺"
        passw = "哈罗 こんにちわ Акїў 😺"
        enc = aes256.encrypt(text, passw)
        dec = aes256.decrypt(enc, passw)
        self.assertEqual(u(text), dec, FAIL)


if __name__ == '__main__':
    unittest.main()

