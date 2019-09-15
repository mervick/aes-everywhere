# AES Everywhere - Cross Language Encryption Library

## Python implementation

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

### Setup
```shell
pip install aes-everywhere
```


### Usage

```python
from AesEverywhere.aes256 import aes256

# encryption
encrypted = aes256().encrypt('TEXT', 'PASSWORD')
print(encrypted)

# decryption
print(aes256().decrypt(encrypted, 'PASSWORD'))
```

