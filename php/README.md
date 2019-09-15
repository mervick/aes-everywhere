# AES Everywhere - Cross Language Encryption Library

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

## PHP implementation

Requirements: php >= 5.3.0

Uses: [OpenSSL Functions](http://php.net/manual/en/ref.openssl.php)

### Installation

```sh
composer require mervick/aes-everywhere
```

### Usage

```php
// encryption
\mervick\aesEverywhere\AES256::encrypt('TEXT', 'PASSWORD')

// decryption
\mervick\aesEverywhere\\AES256::decrypt('ENCRYPTED', 'PASSWORD')
```
