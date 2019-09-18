<?php
/**
 * AES256.php
 * This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
 *
 * This is an implementation of the AES algorithm, specifically CBC mode,
 * with 256 bits key length and PKCS7 padding.
 *
 * Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
 * Licensed under the MIT license
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @author Andrey Izman <izmanw@gmail.com>
 * @license MIT
 */

namespace mervick\aesEverywhere;

/**
 * Class AES256
 * @package mervick\aesEverywhere
 */
class AES256
{
    /**
     * Encrypt string
     *
     * @param string|numeric $text
     * @param string $passphrase
     * @return string
     * @throws \Exception
     */
    public static function encrypt($text, $passphrase)
    {
        $salt = openssl_random_pseudo_bytes(8);

        $salted = $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $passphrase . $salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);

        // encrypt with PKCS7 padding
        return base64_encode('Salted__' . $salt . openssl_encrypt($text . '', 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv));
    }

    /**
     * Decrypt string
     *
     * @param string $encrypted
     * @param string $passphrase
     * @return string|numeric
     * @throws \Exception
     */
    public static function decrypt($encrypted, $passphrase)
    {
        $encrypted = base64_decode($encrypted);
        $salted = substr($encrypted, 0, 8) == 'Salted__';

        if (!$salted) {
            return null;
        }

        $salt = substr($encrypted, 8, 8);
        $encrypted = substr($encrypted, 16);

        $salted = $dx = '';
        while (strlen($salted) < 48) {
            $dx = md5($dx . $passphrase . $salt, true);
            $salted .= $dx;
        }

        $key = substr($salted, 0, 32);
        $iv = substr($salted, 32, 16);

        return openssl_decrypt($encrypted, 'aes-256-cbc', $key, true, $iv);
    }
}
