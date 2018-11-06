# AES Everywhere - Cross Language Encryption Library

## Python implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt


### Usage

```python
from aes256 import aes256

# encryption
print(aes256().encrypt('TEXT', 'PASSWORD'))

# decryption
print(aes256().decrypt('ENCRYPTED', 'PASSWORD'))
```

