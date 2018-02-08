# AES Everywhere - Cross Language Encryption Library

## GoLang implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt


### Usage

```go
import "./aes256"

// encryption
aes256.Encrypt("TEXT", "PASSWORD")

// decryption
aes256.Decrypt("ENCRYPTED", "PASSWORD")
```
