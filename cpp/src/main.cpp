#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "aes256.h"

using namespace std;

int main(int argc, char ** argv)
{
    uint8_t *crypted = AES256::encrypt((const uint8_t *)string("TEXT").c_str(), 4, (const uint8_t *)string("PASS").c_str());
    cout  << crypted << endl;

    uint8_t *decrypted = AES256::decrypt((const uint8_t *)crypted, (const uint8_t *)string("PASS").c_str());
    cout << decrypted << endl;

    return 0;
}
