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

import 'dart:convert' as convert;
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class Aes256 {
  Aes256._();

  static String encrypt(String text, String passphrase) {
    final random = Random.secure();
    List<int> pass = passphrase.split('').map((ch) => ch.codeUnitAt(0)).toList();
    List<int> salt = List<int>.generate(8, (i) => random.nextInt(255));
    List<int> salted = [];
    List<int> dx = [];

    while (salted.length < 48) {
      List<int> data = [...dx, ...pass, ...salt];
      dx = md5.convert(data).bytes;
      salted = [...salted, ...dx];
    }

    final key = Key(Uint8List.fromList(salted.sublist(0, 32)));
    final iv = IV(Uint8List.fromList(salted.sublist(32, 48)));

    final encryptor = Encrypter(AES(key, mode: AESMode.cbc));
    List<int> encrypted = encryptor.encrypt(text, iv: iv).bytes.toList();

    salted = 'Salted__'.split('').map((ch) => ch.codeUnitAt(0)).toList();
    List<int> bytes = [...salted, ...salt, ...encrypted];
    return convert.base64.encode(bytes).toString();
  }

  static String? decrypt(String encoded, String passphrase) {
    List<int> enc = convert.base64.decode(encoded).toList();
    final saltedStr = String.fromCharCodes(enc.sublist(0, 8).toList());
    if (saltedStr != 'Salted__') return null;

    List<int> pass = passphrase.split('').map((ch) => ch.codeUnitAt(0)).toList();
    List<int> salt = enc.sublist(8, 16).toList();
    List<int> text = enc.sublist(16).toList();
    List<int> salted = [];
    List<int> dx = [];

    while (salted.length < 48) {
      List<int> data = [...dx, ...pass, ...salt];
      dx = md5.convert(data).bytes;
      salted = [...salted, ...dx];
    }

    final key = Key(Uint8List.fromList(salted.sublist(0, 32)));
    final iv = IV(Uint8List.fromList(salted.sublist(32, 48)));

    final encryptor = Encrypter(AES(key, mode: AESMode.cbc));
    final encrypted = Encrypted(Uint8List.fromList(text));
    return encryptor.decrypt(encrypted, iv: iv);
  }
}
