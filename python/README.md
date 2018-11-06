# AES Everywhere - Cross Language Encryption Library

## Python implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt


### Usage

```python
from aes256 import aes256

# encryption
encrypted = aes256().encrypt('TEXT', 'PASSWORD')
print(encrypted)

# decryption
print(aes256().decrypt(encrypted, 'PASSWORD'))
```

