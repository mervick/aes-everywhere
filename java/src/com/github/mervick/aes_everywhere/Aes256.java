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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;


public class Aes256
{
    private static final byte[] SALTED = "Salted__".getBytes(US_ASCII);

    /**
     * Encrypt text with the passphrase
     *
     * @param input Input text to encrypt
     * @param passphrase The passphrase
     * @return A base64 encoded string containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static String encrypt(String input, String passphrase) throws Exception
    {
        return Base64.getEncoder().encodeToString(_encrypt(input.getBytes(UTF_8), passphrase.getBytes(UTF_8)));
    }

    /**
     * Encrypt text in bytes with the passphrase
     *
     * @param input Input data in bytes to encrypt
     * @param passphrase The passphrase in bytes
     * @return A base64 encoded bytes containing the encrypted data
     * @throws Exception Throws exceptions
     */
    public static byte[] encrypt(byte[] input, byte[] passphrase) throws Exception
    {
        return Base64.getEncoder().encode(_encrypt(input, passphrase));
    }

    /**
     * Internal encrypt function
     *
     * @param input
     * @param passphrase
     * @return
     * @throws Exception
     */
    private static byte[] _encrypt(byte[] input, byte[] passphrase) throws Exception
    {
        byte[] salt = (new SecureRandom()).generateSeed(8);
        Object[] keyIv = deriveKeyAndIv(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec((byte[])keyIv[0], "AES"), new IvParameterSpec((byte[])keyIv[1]));

        byte[] enc = cipher.doFinal(input);
        return concat(concat(SALTED, salt), enc);
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     *
     * @param crypted Text in bytes to decrypt
     * @param passphrase The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static String decrypt(String crypted, String passphrase) throws Exception
    {
        return new String(decrypt(crypted.getBytes(), passphrase.getBytes(UTF_8)), UTF_8);
    }

    /**
     * Decrypt encrypted base64 encoded text in bytes
     *
     * @param crypted Text in bytes to decrypt
     * @param passphrase The passphrase in bytes
     * @return Decrypted data in bytes
     * @throws Exception Throws exceptions
     */
    public static byte[] decrypt(byte[] crypted, byte[] passphrase) throws Exception
    {
        byte[] data = Base64.getDecoder().decode(crypted);
        byte[] salt = Arrays.copyOfRange(data, 8, 16);

        if (!Arrays.equals(Arrays.copyOfRange(data, 0, 8), SALTED)) {
            throw new IllegalArgumentException("Invalid crypted data");
        }

        Object[] keyIv = deriveKeyAndIv(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec((byte[])keyIv[0], "AES"), new IvParameterSpec((byte[])keyIv[1]));
        return cipher.doFinal(data, 16, data.length - 16);
    }

    /**
     * Derive key and iv
     *
     * @param passphrase Passphrase
     * @param salt Salt
     * @return Array of key and iv
     * @throws Exception Throws exceptions
     */
    private static Object[] deriveKeyAndIv(byte[] passphrase, byte[] salt) throws Exception
    {
        final MessageDigest md5 = MessageDigest.getInstance("MD5");
        final byte[] passSalt = concat(passphrase, salt);
        byte[] dx = new byte[0];
        byte[] di = new byte[0];

        for (int i = 0; i < 3; i++) {
            di = md5.digest(concat(di, passSalt));
            dx = concat(dx, di);
        }

        return new Object[]{Arrays.copyOfRange(dx, 0, 32), Arrays.copyOfRange(dx, 32, 48)};
    }

    /**
     * Concatenate bytes
     *
     * @param a
     * @param b
     * @return Concatenated bytes
     */
    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /**
     * Main function for tests
     * @param args Arguments
     * @throws Exception Throws exceptions
     */
    public static void main(String[] args) throws Exception
    {
        String encrypted = Aes256.encrypt("Java Enc", "PASSWORD");
        System.out.println(encrypted);

        String decrypted = Aes256.decrypt(encrypted, "PASSWORD");
        System.out.println(decrypted);
    }
}
