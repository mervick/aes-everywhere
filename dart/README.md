# AES Everywhere - Cross Language Encryption Library

## Dart implementation

Cipher: AES/256/CBC/PKCS7Padding with random generated salt


### Usage

```dart
// encryption
final encrypted = Aes256.encrypt("TEXT", "PASSWORD")

// decryption
final decrypted = Aes256.decrypt(encrypted, "PASSWORD")
```
