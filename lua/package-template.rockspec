package = "$PACKAGE$"
version = "$VERSION$"
source = {
   url = "git+https://github.com/mervick/aes-everywhere"
}
description = {
   summary = "Cross Language AES256 Encryption Library. Lua implementation",
   detailed = [[
       AES Everywhere is Cross Language Encryption Library which provides the ability
       to encrypt and decrypt data using a single algorithm in different programming 
       languages and on different platforms.
   ]],
   maintainer = "Andrey Izman",
   homepage = "https://github.com/mervick/aes-everywhere",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1, < 5.4",
   "openssl"
}
build = {
   type = "builtin",
   modules = {
      aes_everywhere = "lua/src/aes256.lua"
   }
}
