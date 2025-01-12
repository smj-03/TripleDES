#include <stdio.h>
#include <string.h>
#include "des.h"

extern unsigned char PC1[56];
extern unsigned char PC2[48];
extern unsigned char IP[64];
extern unsigned char IPInv[64];
extern unsigned char nLeftShift[16];
extern unsigned char EBitSelection[48];
extern unsigned char P[32];
extern unsigned char S[8][4][16];

int main(void) {
    const _Bool message[64] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
    const _Bool key[64] = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1};
    _Bool cipher[64];

    // STEP 1 - CREATE 16 SUB KEYS
    _Bool keyPlus[56];
    _Bool keyL[17][28];
    _Bool keyR[17][28];
    _Bool keyBeforePC2[16][56];
    _Bool keyAfterPC2[16][48];

    performPC1(key, PC1, keyPlus);
    printf("PC1\n");
    print_BoolVector(keyPlus, 56);

    partitionRL(keyPlus, 56, keyR[0], keyL[0]);
    print_BoolVector(keyL[0], 28);
    print_BoolVector(keyR[0], 28);

    for (unsigned char i = 1; i <= 16; i++) {
        shift2Left(keyR[i - 1], nLeftShift[i - 1], keyR[i]);
        shift2Left(keyL[i - 1], nLeftShift[i - 1], keyL[i]);
        joinRL(keyBeforePC2[i - 1], 56, keyR[i], keyL[i]);
    }

    print_BoolVector(keyBeforePC2[0], 56);
    print_BoolVector(keyBeforePC2[15], 56);

    for (int i = 0; i < 16; i++)
        performPC2(keyBeforePC2[i], PC2, keyAfterPC2[i]);

    print_BoolVector(keyAfterPC2[0], 48);
    print_BoolVector(keyAfterPC2[15], 48);

    // STEP 2 - ENCODE BLOCKS OF DATA
    _Bool messageL[17][32];
    _Bool messageR[17][32];
    _Bool outputF[32] = {0};
    _Bool preCrypto[64];

    performIP(message, IP, messageR[0], messageL[0]);
    print_BoolVector(messageL[0], 32);
    print_BoolVector(messageR[0], 32);

    for (int i = 1; i <= 16; i++) {
        memcpy(messageL[i], messageR[i - 1], 32 * sizeof(messageR[i][0]));
        functionF(messageR[i - 1], keyAfterPC2[i - 1], EBitSelection, S, P, outputF);
        XOR(messageL[i - 1], outputF, 32, messageR[i]);
    }

    joinRL(preCrypto, 64, messageL[16], messageR[16]);
    print_BoolVector(preCrypto, 64);

    performIPInverse(preCrypto, IPInv, cipher);
    print_BoolVector(cipher, 64);

    unsigned char cipherHex[16];
    vector2Hex(cipher, 64, cipherHex);
    print_HexVector(cipherHex, 16);

    return 0;
}
