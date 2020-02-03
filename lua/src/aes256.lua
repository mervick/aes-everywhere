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

-- Requires openssl command line program

AES256 = {}

AES256.cmd = "echo '%s' | " ..
        "openssl enc -aes-256-cbc -md md5 -a -A -pass pass:'%s'"

AES256.encrypt = function(text, passphrase)
    local handle = io.popen(string.format(AES256.cmd, text, passphrase))
    local result = handle:read("*a")
    handle:close()
    return result
end

AES256.decrypt = function(encrypt, passphrase)
    local cmd = AES256.cmd .. " -d"
    local handle = io.popen(string.format(cmd, encrypt, passphrase))
    local result = handle:read("*a")
    handle:close()
    -- check for newline at the end of the string
    local last_char = string.sub(result, -1)
    if (last_char == '\n') then
        result = string.sub(result, 0, string.len(result)-1)
    end
    return result
end

return AES256;