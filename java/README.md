# AES Everywhere - Cross Language Encryption Library

[AES Everywhere](https://github.com/mervick/aes-everywhere) is Cross Language Encryption Library which provides the ability to encrypt and decrypt data using a single algorithm in different programming languages and on different platforms.

This is an implementation of the AES algorithm, specifically CBC mode, with 256 bits key length and PKCS7 padding.
It implements OpenSSL compatible cryptography with random generated salt


## [Java](https://www.java.com) implementation


### Installation

Via [maven](https://maven.apache.org/), add in dependencies of your `pom.xml`:

```xml
<dependencies>
  <dependency>
    <groupId>com.github.mervick</groupId>
    <artifactId>aes-everywhere-java</artifactId>
    <version>1.2.7</version>
  </dependency>
</dependencies>
```

Via [gradle](https://gradle.org/), add in dependencies of your `build.gradle`:
```
dependencies {
  implementation 'com.github.mervick:aes-everywhere-java:1.2.7'
}
```

Building from the sources:

```bash
mvn package 
```


### Import Aes256 in your project


**Java &gt;= 8**

```java
import com.github.mervick.aes_everywhere.Aes256;

```

**Android with API level &lt; 26 or Java &lt; 8**  
(also in case if you get error about java.util.Base64)

```java
import com.github.mervick.aes_everywhere.legacy.Aes256;
```

### Usage

```java
String text = "TEXT";
String pass = "PASSWORD";

byte[] text_bytes = text.getBytes("UTF-8");
byte[] pass_bytes = pass.getBytes("UTF-8");

// strings encryption
String encrypted = Aes256.encrypt(text, pass);
System.out.println(encrypted);

// bytes encryption
byte[] encrypted_bytes = Aes256.encrypt(text_bytes, pass_bytes);
System.out.println(encrypted_bytes);

// strings decryption
String decrypted = Aes256.decrypt(encrypted, pass);
System.out.println(decrypted);

// bytes decryption
byte[] decrypted_bytes = Aes256.decrypt(encrypted_bytes, pass_bytes);
System.out.println(decrypted_bytes);
```

## Known issues

[java.security.InvalidKeyException: Illegal key size](https://github.com/mervick/aes-everywhere/issues/5)

This exception throws because of a restriction imposed by the default JDK. On the default JDK installation AES is limited to 128 bit key size.
