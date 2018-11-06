# AES Everywhere - Cross Language Encryption Library

## Java implementation

Cipher: AES/256/CBC/PKCS5Padding with random generated salt

### Usage

```java
import dev.mervick.Aes256;

// [...]

// encryption
String encrypted = Aes256.encrypt("TEXT", "PASSWORD");
System.out.println(encrypted);

// decryption
String decrypted = Aes256.decrypt(encrypted, "PASSWORD");
System.out.println(decrypted);

```

#### Android with API level &lt; 26:

```java
import dev.mervick.android.Aes256;

// [...]

// encryption
String encrypted = Aes256.encrypt("TEXT", "PASSWORD");
System.out.println(encrypted);

// decryption
String decrypted = Aes256.decrypt(encrypted, "PASSWORD");
System.out.println(decrypted);
```

## Known issues

[java.security.InvalidKeyException: Illegal key size](https://github.com/mervick/aes-everywhere/issues/5)

This exception is thrown because of a restriction imposed by default JDK. On a default JDK installation, AES is limited to 128 bit key size.
