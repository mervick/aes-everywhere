# AES Everywhere - Cross Language Encryption Library

AES Everywhere is Cross Language Encryption Library which provides the ability to encrypt and decrypt data using a single algorithm in different programming languages and on different platforms.

This is an implementation of the AES algorithm, specifically CBC mode, with 256 bits key length and PKCS7 padding.
It implements OpenSSL compatible cryptography with random generated salt


## [Ruby](https://www.ruby-lang.org) implementation

### Installation

```shell
gem install aes-everywhere
```

or add in your `Gemfile`
```ruby
gem 'aes-everywhere'
```


### Usage

```ruby
require "aes-everywhere"

# encryption
encrypted = AES256.encrypt("TEXT", "PASSWORD")
puts encrypted

# decryption
decrypted = AES256.decrypt(ct, "PASSWORD")
puts decrypted
```

