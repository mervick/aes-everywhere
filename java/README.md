# AES Everywhere - Cross Language Encryption Library

## Java implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt

### Usage

```js
import mervick.aesEverywhere.AES256;

// [...]

// encryption
String encrypted = AES256.encrypt("TEXT", "PASSWORD"));
System.out.println(encrypted);

// decryption
String decrypted = AES256.decrypt("ENCRYPTED", "PASSWORD"));
System.out.println(decrypted);

```
