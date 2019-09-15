# AES Everywhere - Cross Language Encryption Library

## C# implementation

Cipher: AES/256/CBC/PKCS7Padding with random generated salt


### Usage

```cs
using AesEverywhere;

AES256 aes = new AES256();

// encryption
string crypted = aes.Encrypt("TEXT", "PASSWORD");

// decryption
string decrypted = aes.Decrypt(crypted, "PASSWORD");
```

