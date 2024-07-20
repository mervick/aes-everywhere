/// aeseverywhere.dart
/// This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
///
/// This is an implementation of the AES algorithm, CBC mode,
/// with 256 bits key length and PKCS7 padding.
///
/// Copyright Andrey Izman (c) 2018-2022 <izmanw@gmail.com>
/// Licensed under the MIT license
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

library aeseverywhere;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class Aes256 {
  Aes256._();

  static List<int> _generateSaltedKeyAndIv(String passphrase, List<int> salt) {
    final pass = utf8.encode(passphrase);
    var dx = <int>[];
    var salted = <int>[];

    while (salted.length < 48) {
      final data = dx + pass + salt;
      dx = md5.convert(data).bytes;
      salted.addAll(dx);
    }

    return salted;
  }

  static String encrypt(String text, String passphrase) {
    final random = Random.secure();
    final salt = List<int>.generate(8, (_) => random.nextInt(256));
    final salted = _generateSaltedKeyAndIv(passphrase, salt);

    final key = Key(Uint8List.fromList(salted.sublist(0, 32)));
    final iv = IV(Uint8List.fromList(salted.sublist(32, 48)));
    final encryptor = Encrypter(AES(key, mode: AESMode.cbc));

    final encrypted = encryptor.encrypt(text, iv: iv).bytes;
    final saltedPrefix = utf8.encode('Salted__');
    final result = saltedPrefix + salt + encrypted;

    return base64.encode(result);
  }

  static String? decrypt(String encoded, String passphrase) {
    final enc = base64.decode(encoded);
    final saltedPrefix = utf8.decode(enc.sublist(0, 8));

    if (saltedPrefix != 'Salted__') return null;

    final salt = enc.sublist(8, 16);
    final text = enc.sublist(16);
    final salted = _generateSaltedKeyAndIv(passphrase, salt);

    final key = Key(Uint8List.fromList(salted.sublist(0, 32)));
    final iv = IV(Uint8List.fromList(salted.sublist(32, 48)));
    final encryptor = Encrypter(AES(key, mode: AESMode.cbc));

    return encryptor.decrypt(Encrypted(Uint8List.fromList(text)), iv: iv);
  }
}
