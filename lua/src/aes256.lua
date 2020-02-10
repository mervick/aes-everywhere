-- aes256.lua
-- This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
--
-- This is an implementation of the AES algorithm, specifically CBC mode,
-- with 256 bits key length and PKCS7 padding.
--
-- Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
-- Copyright Philip Mayer (c) 2020 <philip.mayer@shadowsith.de>
-- Licensed under the MIT license
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

-- Requires lua-openssl (luarocks install openssl)

local openssl = require "openssl"
local md5 = openssl.digest.get('md5')

-- private
local function deriveKeyAndIv(passphrase, salt)
    local di = ""
    local dx = ""

    for i = 1, 4 do
        di = md5:digest(di .. passphrase .. salt)
        dx = dx .. di
    end
    return string.sub(dx, 0, 32), string.sub(dx, 33, 48)
end

-- public

AES256 = {}

AES256.encrypt = function(input, passphrase)
    local salt = openssl.random(8)
    local key, iv = deriveKeyAndIv(passphrase, salt)
    local aes = openssl.cipher.new('aes-256-cbc', true, key, iv, true, openssl.engine('pkcs7'))
    local crypted = aes:update(input) .. aes:final()
    return openssl.base64("Salted__" .. salt .. crypted, true)
end

AES256.decrypt = function(crypted, passphrase)
    local data = openssl.base64(crypted, false)
    local salted = string.sub(data, 0, 8)
    if salted ~= "Salted__" then
        error("Invalid data")
    end
    local salt = string.sub(data, 9, 16)
    crypted = string.sub(data, 17, string.len(data))
    local key, iv = deriveKeyAndIv(passphrase, salt)
    local aes = openssl.cipher.new('aes-256-cbc', false, key, iv, true, openssl.engine('pkcs7'))
    crypted = aes:update(crypted) .. aes:final()
    return crypted
end

return AES256;