/**
 * aes256.js
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */
/* jshint node: true */
'use strict';

const CryptoJS = require('node-cryptojs-aes').CryptoJS;

const ConcatFormatter = {
    stringify(params) {
        return params.salt.toString() + params.iv.toString() + params.ciphertext.toString(CryptoJS.enc.Base64);
    },
    parse(str) {
        const ct = str.substr(48),
            iv = str.substr(16, 32),
            salt = str.substr(0, 16);

        return CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(ct),
            iv: CryptoJS.enc.Hex.parse(iv),
            salt: CryptoJS.enc.Hex.parse(salt)
        });
    }
};

const JsonFormatter = {
    stringify(params) {
        return JSON.stringify({
            ct: params.ciphertext.toString(CryptoJS.enc.Base64),
            iv: params.iv.toString(),
            s: params.salt.toString()
        });
    },

    parse(json) {
        const data = JSON.parse(json);

        return CryptoJS.lib.CipherParams.create({
            ciphertext: CryptoJS.enc.Base64.parse(data.ct),
            iv: CryptoJS.enc.Hex.parse(data.iv),
            salt: CryptoJS.enc.Hex.parse(data.s)
        });
    }
};

const AES256 = {
    encrypt(input, passphrase, format = 'concat') {
        if (format.toLowerCase() == 'concat') {
            format = ConcatFormatter;
        } else {
            format = JsonFormatter;
        }
        return CryptoJS.AES.encrypt(input, passphrase, {format}).toString();
    },

    decrypt(crypted, passphrase, format = 'concat') {
        if (format.toLowerCase() == 'concat') {
            format = ConcatFormatter;
        } else {
            format = JsonFormatter;
        }
        return CryptoJS.AES.decrypt(crypted, passphrase, {format}).toString(CryptoJS.enc.Utf8);
    }
};

module.exports = AES256;
