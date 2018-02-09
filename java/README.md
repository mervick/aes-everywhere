# AES Everywhere - Cross Language Encryption Library

## Java implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt

### Usage

```js
import dev.mervick.Aes256;

// [...]

// encryption
String encrypted = Aes256.encrypt("TEXT", "PASSWORD"));
System.out.println(encrypted);

// decryption
String decrypted = Aes256.decrypt("ENCRYPTED", "PASSWORD"));
System.out.println(decrypted);

```
