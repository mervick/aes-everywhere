# aes256.rb
# This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
#
# This is an implementation of the AES algorithm, specifically CBC mode,
# with 256 bits key length and PKCS7 padding.
#
# Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


require "openssl"
require "digest"
require "base64"


class AES256
  def self.encrypt(input, passphrase)
    salt = OpenSSL::Random.random_bytes(8)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt
    cipher.key, cipher.iv = self.derive_key_and_iv(passphrase, salt)
    crypted = cipher.update(input) + cipher.final
    Base64.strict_encode64("Salted__" + salt + crypted)
  end

  def self.decrypt(crypted, passphrase)
    data = Base64.strict_decode64(crypted)
    salted = data[0..7]
    if salted != "Salted__"
      raise "Invalid data"
    end
    salt = data[8..15]
    crypted = data[16..-1]
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt
    cipher.key, cipher.iv = self.derive_key_and_iv(passphrase, salt)
    derypted = cipher.update(crypted) + cipher.final
    derypted.force_encoding("utf-8")
  end

  private

  def self.derive_key_and_iv(passphrase, salt)
    dx = di = ""
    enc_pass = passphrase.encode("iso-8859-1")

    for _ in 1...4
      di = Digest::MD5.digest(di + enc_pass + salt)
      dx += di
    end

    return dx[0..31], dx[32..47]
  end
end


data = "Data 😄 текст"
pass = "pass"

ct = AES256.encrypt(data, pass)
tx = AES256.decrypt(ct, pass)

puts ct
puts tx

# enc   = Base64.encode64('Send reinforcements')
# # -> "U2VuZCByZWluZm9yY2VtZW50cw==\n"
# plain = Base64.decode64(enc)
# # -> "Send reinforcements"
#
#
# puts salt
#
# cipher = OpenSSL::Cipher::AES256.new(:CBC)
# cipher.encrypt
#
#
# cipher.key = key
# cipher.iv = nonce
#
# encrypted = cipher.update(data) + cipher.final
#
#
#
#
# decipher = OpenSSL::Cipher::AES.new(256, :CBC)
# decipher.decrypt
# decipher.key = key
# decipher.iv = iv
#
# plain = decipher.update(encrypted) + decipher.final
#
# puts data == plain #=> true
#
