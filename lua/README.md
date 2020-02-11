# AES Everywhere - Cross Language Encryption Library

Cipher: AES/256/CBC/PKCS7Padding with random generated salt

## Lua implementation

Requirements: [openssl](https://luarocks.org/modules/zhaozg/openssl) package  

Installation via [luarocks](https://github.com/luarocks/luarocks) package manager:  
```
luarocks install aes_everywhere
```

### Usage

```lua
local AES256 = require("aes_everywhere")

-- encryption
local enc = AES256.encrypt('TEXT', 'PASSWORD')

-- decryption
local dec = AES256.decrypt('ENCRYPTED', 'PASSWORD')
```

