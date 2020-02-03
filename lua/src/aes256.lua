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