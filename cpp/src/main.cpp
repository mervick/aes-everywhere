#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "aes256.h"

using namespace std;

int main(int argc, char ** argv)
{
    uint8_t *crypted = AES256::encrypt((const uint8_t *)"TEXT", 4, (const uint8_t *)"PASS");
    cout  << crypted << endl;

    uint8_t *decrypted = AES256::decrypt((const uint8_t *)crypted, (const uint8_t *)"PASS");
    cout << decrypted << endl;

    return 0;
}
