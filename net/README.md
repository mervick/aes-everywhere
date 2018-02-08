# AES Everywhere - Cross Language Encryption Library

## C# implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt


### Usage

```cs
using AesEverywhere;

AES256 aes = new AES256();

// encryption
string ct = aes.Encrypt("TEXT", "PASSWORD");

// decryption
string dec = aes.Decrypt("ENCRYPTED", "PASSWORD");
```

