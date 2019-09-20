/// aes256.h
/// This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
///
/// This is an implementation of the AES algorithm, specifically CBC mode,
/// with 256 bits key length and PKCS7 padding.
/// The implementation is verified against the test vectors in:
/// National Institute of Standards and Technology Special Publication 800-38A 2001 ED
///
/// Aes implementation by Tiny AES contributors (https://github.com/kokke/tiny-AES-c)
///
/// @copyright Tiny-AES contributors (c) 2014-2019
/// @copyright Andrey Izman (c) 2018-2019
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef _AES256_H_
#define _AES256_H_

#include <string>
#include <stdint.h>


/// AES256 class.
class AES256
{
public:
    /// Encrypt string using passphrase
    ///
    /// @param input Input string
    /// @param len Input length
    /// @param passphrase Passphrase
    /// @return Encrypted string
    static uint8_t* encrypt(const uint8_t* input, const size_t len, const uint8_t* passphrase);

    /// Encrypt string using passphrase
    ///
    /// @param input Input string
    /// @param passphrase Passphrase
    /// @return Encrypted string
    static std::string encrypt(const std::string input, const std::string passphrase);

    /// Decrypt encrypted string using passphrase
    ///
    /// @param crypted Input string
    /// @param passphrase Passphrase
    /// @return Decrypted string
    static uint8_t* decrypt(const uint8_t* input, const uint8_t* passphrase);

    /// Decrypt encrypted string using passphrase
    ///
    /// @param crypted Input string
    /// @param passphrase Passphrase
    /// @return Decrypted string
    static std::string decrypt(const std::string input, const std::string passphrase);
};

#endif //_AES256_H_
