# AES Everywhere - Cross Language Encryption Library

## GoLang implementation

Cipher: AES/256/CBC/PKCS7Padding with random generated salt


### Usage

```go
import "github.com/mervick/aes-everywhere/go/aes256"

// encryption
encrypted := aes256.Encrypt("TEXT", "PASSWORD")

// decryption
decrypted := aes256.Decrypt(encrypted, "PASSWORD")
```
