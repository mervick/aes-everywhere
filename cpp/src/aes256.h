/*!
 * aes256.h
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018-2019
 * @license LGPL
 */

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
