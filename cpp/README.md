# AES Everywhere - Cross Language Encryption Library

## C++ implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt

### Usage

```cpp
// encryption
std::string encrypted = AES256::encrypt("TEXT", "PASSWORD"));

// decryption
std::string decrypted = AES256::decrypt("ENCRYPTED", "PASSWORD"));
```

