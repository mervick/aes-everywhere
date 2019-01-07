/**
 * aes256.js
 * AES Everywhere - Cross Language Encryption Library
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */
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
