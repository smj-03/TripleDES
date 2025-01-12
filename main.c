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

void createSubkeys(const _Bool*, _Bool [16][48]);
void reverseSubkeys(const _Bool [16][48], _Bool [16][48]);
void desEncryption(const _Bool*, const _Bool [16][48], _Bool*);

void tripleDesEncryption(const _Bool* message, const _Bool subkeys[3][16][48], _Bool* cipher);

int main(void) {
    const _Bool message[64] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
    const _Bool key[64] = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1};

    _Bool subkeys[16][48];
    _Bool cipher[64];

    // STEP 1 - CREATE 16 SUB KEYS
    createSubkeys(key, subkeys);

    // STEP 2 - ENCODE BLOCKS OF DATA
    desEncryption(message, subkeys, cipher);

    unsigned char messageHex[16];
    vector2Hex(message, 64, messageHex);
    print_HexVector(messageHex, 16);

    unsigned char cipherHex[16];
    vector2Hex(cipher, 64, cipherHex);
    print_HexVector(cipherHex, 16);

    // DECRYPTION
    _Bool reversedSubkeys[16][48];
    reverseSubkeys(subkeys, reversedSubkeys);
    _Bool decryptedMessage[64];
    unsigned char decryptedHex[16];
    desEncryption(cipher, reversedSubkeys, decryptedMessage);
    vector2Hex(decryptedMessage, 64, decryptedHex);
    print_HexVector(decryptedHex, 16);

    return 0;
}

void createSubkeys(const _Bool* key, _Bool subkeys[16][48]) {
    _Bool keyPlus[56];
    _Bool keyL[17][28];
    _Bool keyR[17][28];
    _Bool keyBeforePC2[16][56];

    performPC1(key, PC1, keyPlus);
    partitionRL(keyPlus, 56, keyR[0], keyL[0]);

    for (unsigned char i = 1; i <= 16; i++) {
        shift2Left(keyR[i - 1], nLeftShift[i - 1], keyR[i]);
        shift2Left(keyL[i - 1], nLeftShift[i - 1], keyL[i]);
        joinRL(keyBeforePC2[i - 1], 56, keyR[i], keyL[i]);
    }

    for (int i = 0; i < 16; i++)
        performPC2(keyBeforePC2[i], PC2, subkeys[i]);
}

void reverseSubkeys(const _Bool originalSubkeys[16][48], _Bool reversedSubkeys[16][48]) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 48; j++) {
            reversedSubkeys[i][j] = originalSubkeys[i][j];
        }
    }

    for (int i = 0; i < 8; i++) {
        _Bool temp[48];
        for (int j = 0; j < 48; j++) {
            temp[j] = reversedSubkeys[i][j];
            reversedSubkeys[i][j] = reversedSubkeys[15 - i][j];
            reversedSubkeys[15 - i][j] = temp[j];
        }
    }
}

void desEncryption(const _Bool* message, const _Bool subkeys[16][48], _Bool* cipher) {
    _Bool messageL[17][32];
    _Bool messageR[17][32];
    _Bool outputF[32] = {0};
    _Bool preCrypto[64];

    performIP(message, IP, messageR[0], messageL[0]);

    for (int i = 1; i <= 16; i++) {
        memcpy(messageL[i], messageR[i - 1], 32 * sizeof(messageR[i][0]));
        functionF(messageR[i - 1], subkeys[i - 1], EBitSelection, S, P, outputF);
        XOR(messageL[i - 1], outputF, 32, messageR[i]);
    }

    joinRL(preCrypto, 64, messageL[16], messageR[16]);
    performIPInverse(preCrypto, IPInv, cipher);
}

void tripleDesEncryption(const _Bool* message, const _Bool subkeys[3][16][48], _Bool* cipher) {
    _Bool cipher1[64];
    _Bool cipher2[64];

    desEncryption(message, subkeys[0], cipher1);
    desEncryption(cipher2, subkeys[1], cipher1);
    desEncryption(cipher2, subkeys[2], cipher);
}