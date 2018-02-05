/*!
 * aes256.h
 * @author Andrey Izman <izmanw@gmail.com>
 * @copyright Andrey Izman (c) 2018
 * @license MIT
 */

#ifndef MERVICK_AES256_H
#define MERVICK_AES256_H

#include <stdio.h>
#include <string.h>

using namespace std;


//! AES256 class.
class AES256
{
public:
    static string encrypt(string text, string passphrase);
    static string decrypt(string text, string passphrase);

protected:
    static string encryptFinal(unsigned char *text, int text_len, unsigned char *key, unsigned char *iv);
    static string decryptFinal(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv);
};

#endif
