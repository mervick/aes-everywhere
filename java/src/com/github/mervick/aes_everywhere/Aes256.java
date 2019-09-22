// Aes256.java
// This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
//
// This is an implementation of the AES algorithm, specifically CBC mode,
// with 256 bits key length and PKCS7 padding.
//
// Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package com.github.mervick.aes_everywhere;

import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;


public class Aes256 extends AbstractAes256
{
    /**
     * Encrypt text with the passphrase
     * @param input Input text to encrypt
     * @param passphrase The passphrase
     * @return A base64 encoded string containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static String encrypt(String input, String passphrase) throws Exception {
        return Base64.getEncoder().encodeToString(_encrypt(input.getBytes(UTF_8), passphrase.getBytes(UTF_8)));
    }

    /**
     * Encrypt text in bytes with the passphrase
     * @param input Input data in bytes to encrypt
     * @param passphrase The passphrase in bytes
     * @return A base64 encoded bytes containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static byte[] encrypt(byte[] input, byte[] passphrase) throws Exception {
        return Base64.getEncoder().encode(_encrypt(input, passphrase));
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     * @param crypted Text in bytes to decrypt
     * @param passphrase The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static String decrypt(String crypted, String passphrase) throws Exception {
        return new String(_decrypt(Base64.getDecoder().decode(crypted), passphrase.getBytes(UTF_8)), UTF_8);
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     * @param crypted Text in bytes to decrypt
     * @param passphrase The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static byte[] decrypt(byte[] crypted, byte[] passphrase) throws Exception {
        return _decrypt(Base64.getDecoder().decode(crypted), passphrase);
    }
}
