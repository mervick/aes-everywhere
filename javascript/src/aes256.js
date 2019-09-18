// aes256.js
// This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
//
// This is an implementation of the AES algorithm, specifically CBC mode,
// with 256 bits key length and PKCS7 padding.
//
// Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
// Licensed under the MIT license
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

/* jshint node: true */
'use strict';

var CryptoJS = require('node-cryptojs-aes').CryptoJS;

var OpenSslFormatter = {
    stringify(params) {
        var salt = CryptoJS.enc.Hex.parse(params.salt.toString()).toString(CryptoJS.enc.Latin1);
        var ct = params.ciphertext.toString(CryptoJS.enc.Latin1);

        return CryptoJS.enc.Latin1.parse('Salted__' + salt + ct).toString(CryptoJS.enc.Base64);
    },

    parse(str) {
        var str = CryptoJS.enc.Base64.parse(str).toString(CryptoJS.enc.Latin1);
        var salted = str.substr(0, 8);

        if (salted !== 'Salted__') {
            throw new Error('Error parsing salt');
        }

        var salt = str.substr(8, 8);
        var ct = str.substr(16);

        return CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Latin1.parse(ct),
            salt: CryptoJS.enc.Latin1.parse(salt)
        });
    }
};

var AES256 = {
    encrypt: function(input, passphrase) {
        return CryptoJS.AES.encrypt(input, passphrase, {format: OpenSslFormatter}).toString();
    },

    decrypt: function(crypted, passphrase) {
        return CryptoJS.AES.decrypt(crypted, passphrase, {format: OpenSslFormatter}).toString(CryptoJS.enc.Utf8);
    }
};

module.exports = AES256;
if (window) window.AES256 = AES256;
