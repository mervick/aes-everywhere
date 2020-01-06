# AES Everywhere - Cross Language Encryption Library

AES Everywhere is Cross Language Encryption Library which provides the ability to encrypt and decrypt data using a single algorithm in different programming languages and on different platforms.

This is an implementation of the AES algorithm, specifically CBC mode, with 256 bits key length and PKCS7 padding.
It implements OpenSSL compatible cryptography with random generated salt


## [Python](https://www.python.org/) implementation

Python versions >= 2.7, < 3.8

### Installation
```shell
pip install aes-everywhere
```


### Usage

```python
from AesEverywhere import aes256

# encryption
encrypted = aes256.encrypt('TEXT', 'PASSWORD')
print(encrypted)

# decryption
print(aes256.decrypt(encrypted, 'PASSWORD'))
```

### Known bugs

AttributeError: module 'time' has no attribute 'clock' with python 3.8  
ref https://github.com/mervick/aes-everywhere/issues/21
