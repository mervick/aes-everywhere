# AES Everywhere - Cross Language Encryption Library

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

## Lua implementation

Requirements: luarocks (lua package manager)<br>
`luarocks install openssl`

### Usage

```lua
local AES256 = require("aes256")

-- encryption
local enc = AES256.encrypt('TEXT', 'PASSWORD')

-- decryption
local dec = AES256.decrypt('ENCRYPTED', 'PASSWORD')
```

