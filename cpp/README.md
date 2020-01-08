# AES Everywhere - Cross Language Encryption Library

## C++ implementation

### Attention. Work is in progress, the current implementation is buggy and requires a complete rewrite. Don't use it

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

### Usage

Using `string`s:
```cpp
#include <string.h>
#include "aes256.h"

std::string text = std::string("TEXT");
std::string passphrase = std::string("PASSPHRASE");

std::string encrypted = AES256::encrypt(text, passphrase);
std::string decrypted = AES256::decrypt(encrypted, passphrase);
```

Using `uint8_t*`:
```cpp
#include <stdint.h>
#include "aes256.h"

uint8_t *text = (uint8_t *)"TEXT";
uint8_t *passphrase = (uint8_t *)"PASSPHRASE";

uint8_t *encrypted = AES256::encrypt(text, strlen((char *)text), passphrase));
uint8_t *decrypted = AES256::decrypt(encrypted, passphrase));
```
