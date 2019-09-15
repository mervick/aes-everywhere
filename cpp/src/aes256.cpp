/*!
 * aes256.cpp
 * This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
 *
 * This is an implementation of the AES algorithm, specifically CBC mode, with block size 256b.
 * The implementation is verified against the test vectors in:
 * National Institute of Standards and Technology Special Publication 800-38A 2001 ED
 *
 * Aes implementation by Tiny AES contributors (https://github.com/kokke/tiny-AES-c)
 *
 * @copyright Tiny-AES contributors (c) 2014-2019
 * @copyright Andrey Izman (c) 2018-2019
 *
 * @license LGPL
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "aes256.h"
#include "md5.h"
#include "base64.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/

#define AES_SALTLEN       8
#define AES_SALTEDLEN     8
#define AES_BLOCKLEN      16
#define AES_KEYLEN        32
#define AES_keyExpSize    240

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#define Nk 8
#define Nr 14

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
    #define MULTIPLY_AS_A_FUNCTION 0
#endif

using namespace std;

struct AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
};

// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
//  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#ifdef AES_DEBUG
// prints string as hex
static void phex(uint8_t* str, uint8_t len = 16)
{
    for (uint8_t i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}
#endif

/*
static uint8_t getSBoxValue(uint8_t num)
{
    return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
    return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
    unsigned i, j, k;
    uint8_t temp[4]; // Used for the column/row operations

    // The first round key is the key itself.
    for (i = 0; i < Nk; ++i)
    {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    // All other round keys are found from the previous round keys.
    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            temp[0] = RoundKey[k + 0];
            temp[1] = RoundKey[k + 1];
            temp[2] = RoundKey[k + 2];
            temp[3] = RoundKey[k + 3];

        }

        if (i % Nk == 0)
        {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            {
                const uint8_t u8tmp = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = u8tmp;
            }

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            {
                temp[0] = getSBoxValue(temp[0]);
                temp[1] = getSBoxValue(temp[1]);
                temp[2] = getSBoxValue(temp[2]);
                temp[3] = getSBoxValue(temp[3]);
            }

            temp[0] = temp[0] ^ Rcon[i/Nk];
        }

        if (i % Nk == 4)
        {
            // Function Subword()
            {
                temp[0] = getSBoxValue(temp[0]);
                temp[1] = getSBoxValue(temp[1]);
                temp[2] = getSBoxValue(temp[2]);
                temp[3] = getSBoxValue(temp[3]);
            }
        }

        j = i * 4; k=(i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ temp[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ temp[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ temp[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ temp[3];
    }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
    uint8_t i,j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;

    for (i = 0; i < 4; ++i)
    {
        t     = (*state)[i][0];
        Tmp   = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm    = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm    = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm    = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm    = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//             The compiler seems to be able to vectorize the operation better this way.
//             See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
           ((y>>1 & 1) * xtime(x)) ^
           ((y>>2 & 1) * xtime(xtime(x))) ^
           ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
           ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}
#else
#define Multiply(x, y)                                           \
                (  ((y & 1) * x) ^                               \
                ((y>>1 & 1) * xtime(x)) ^                        \
                ((y>>2 & 1) * xtime(xtime(x))) ^                 \
                ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^          \
                ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))    \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
    int i;
    uint8_t a, b, c, d;

    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}

static void InvShiftRows(state_t* state)
{
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = 1; round < Nr; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(Nr, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr-1 rounds are executed in the loop below.
    for (round = (Nr - 1); round > 0; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
    uint8_t i;
    for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
    {
        buf[i] ^= Iv[i];
    }
}

static void CBCEncrypt(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
    uintptr_t i;
    uint8_t* Iv = ctx->Iv;

    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        XorWithIv(buf, Iv);
        Cipher((state_t*)buf, ctx->RoundKey);
        Iv = buf;
        buf += AES_BLOCKLEN;
    }
}

static void CBCDecrypt(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
    uintptr_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        InvCipher((state_t*)buf, ctx->RoundKey);
        XorWithIv(buf, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}

static uint8_t xRandom()
{
    static unsigned int k = 21;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (11 * k++ + tv.tv_sec * 3 + tv.tv_usec);
}

static uint8_t* RandomBytes(size_t size)
{
    uint8_t* stream = (uint8_t*)malloc(size);

    for (size_t i = 0; i < size; i++) {
        stream[i] = xRandom() % 254 + 1;
    }

    return stream;
}

static uint8_t* Pkcs7Padding(uint8_t* buf, uint32_t len)
{
    char npad = 16 - len % 16;
    char* pad = &npad;

    uint8_t* buf2 = (uint8_t*)malloc(len + (uint8_t)npad);
    strncpy((char*)buf2, (char*)buf, len);

    for (char i = 0; i < npad; i++) {
        strncat((char*)buf2, pad, 1);
    }

    buf2[len] = '\0';
    return buf2;
}

static void Pkcs7Trimming(uint8_t* buf, size_t len)
{
    buf[len - buf[len - 1]] = '\0';
}

static void DeriveKeyIv(struct AES_ctx* ctx, uint8_t* pass, uint8_t* salt)
{
    char* dx = (char*)malloc(strlen((char*)pass) + AES_SALTLEN);

    strcpy(dx, (char*)pass);
    strcat(dx, (char*)salt);

    char* d = (char*)malloc(AES_KEYLEN + AES_BLOCKLEN);
    char* d_i = (char*)malloc(AES_BLOCKLEN);

    for (uint8_t i = 1; i <= 3; i++) {
        char* didx = (char*)malloc(strlen(dx) + i * 16);
        strcpy(didx, d_i);
        strcat(didx, dx);
        strcpy(d_i, MD5(didx).binary().c_str());
        strncat(d, d_i, AES_BLOCKLEN);
    }

    uint8_t key[AES_KEYLEN];
    strncpy((char*)key, (char*)d, AES_KEYLEN);

    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, d + AES_KEYLEN, AES_BLOCKLEN);
}

/*****************************************************************************/
/* Public methods:                                                           */
/*****************************************************************************/

/// Encrypt string using passphrase
///
/// @param input Input string
/// @param len Input length
/// @param passphrase Passphrase
/// @return Encrypted string
uint8_t* AES256::encrypt(const uint8_t* input, const size_t len, const uint8_t* passphrase)
{
    uint8_t* crypted = (uint8_t*)malloc(0);

    do {
        struct AES_ctx ctx;

        uint8_t* buf = Pkcs7Padding((uint8_t*)input, len);
        size_t padlen = len + AES_BLOCKLEN - len % AES_BLOCKLEN;
        uint8_t* salt = (uint8_t*)RandomBytes(AES_SALTLEN);

        DeriveKeyIv(&ctx, (uint8_t*)passphrase, salt);
        CBCEncrypt(&ctx, buf, padlen);

        size_t rlen = padlen + AES_BLOCKLEN;
        uint8_t* salted = (uint8_t*)malloc(rlen);

        strncpy((char*)salted, (char*)"Salted__", AES_SALTLEN);
        strncpy((char*)salted + AES_SALTLEN, (char*)salt, AES_SALTLEN);
        strncpy((char*)salted + AES_BLOCKLEN, (char*)buf, padlen);

        string encoded = base64_encode(salted, rlen);

        size_t cryptedLen = encoded.length() + 1;
        crypted = (uint8_t*)realloc(crypted, cryptedLen);
        strncpy((char*)crypted, (char*)encoded.c_str(), cryptedLen);
    }
    // with some IV it creates invalid output, so check it before return
    while (strcmp((char*)input, (char*)decrypt(crypted, passphrase)) != 0);

    return crypted;
}

/// Encrypt string using passphrase
///
/// @param input Input string
/// @param passphrase Passphrase
/// @return Encrypted string
string AES256::encrypt(const string input, const string passphrase)
{
    return string((char*)encrypt((const uint8_t*)input.c_str(),
                                 (const size_t)input.length(),
                                 (const uint8_t*)passphrase.c_str()));
}

/// Decrypt encrypted string using passphrase
///
/// @param crypted Input string
/// @param passphrase Passphrase
/// @return Decrypted string
uint8_t* AES256::decrypt(const uint8_t* crypted, const uint8_t* passphrase)
{
    struct AES_ctx ctx;

    string b64 = base64_decode(string((char*)crypted));
    size_t len = b64.length() + 1;

    uint8_t* decoded = (uint8_t *)b64.c_str();
    uint8_t salted[AES_SALTLEN];
    uint8_t salt[AES_SALTLEN];

    strncpy((char*)salted, (char*)decoded, AES_SALTLEN);
    strncpy((char*)salt, (char*)decoded + AES_SALTLEN, AES_SALTLEN);

    if (strncmp((char*)salted, (char*)"Salted__", AES_SALTLEN) != 0)
        return (uint8_t *)"";

    size_t outLen = len - AES_BLOCKLEN;
    uint8_t* buf = (uint8_t*)malloc(outLen);
    strncpy((char*)buf, (char*)decoded + AES_BLOCKLEN, outLen);

    DeriveKeyIv(&ctx, (uint8_t*)passphrase, salt);
    CBCDecrypt(&ctx, buf, outLen);
//    Pkcs7Trimming(buf, outLen);

    return (uint8_t*)buf;
}

/// Decrypt encrypted string using passphrase
///
/// @param crypted Input string
/// @param passphrase Passphrase
/// @return Decrypted string
string AES256::decrypt(const string input, const string passphrase)
{
    return string((char*)decrypt((const uint8_t*)input.c_str(),
                                 (const uint8_t*)passphrase.c_str()));
}
