//
// Created by Szymon on 1/11/2025.
//

#include <stdio.h>
#include <string.h>
#include "des.h"

void performPC1(const _Bool* key, const unsigned char* PC1, _Bool* newKey) {
    for (unsigned char i = 0; i < 56; i++)
        newKey[i] = key[PC1[i] - 1];
}

void partitionRL(const _Bool* vector, unsigned char length, _Bool* keyR, _Bool* keyL) {
    for (int i = 0; i < ( length / 2 ); i++) {
        keyL[i] = vector[i];
        keyR[i] = vector[i + (length / 2)];
    }
}

void shift2Left(const _Bool* iVector, unsigned char nShifts, _Bool* oVector) {
    unsigned char bitCtrl;
    constexpr unsigned char nBits = 28;
    _Bool iVectorTmp[28];

    for (bitCtrl = 0; bitCtrl < nBits; bitCtrl++)
        iVectorTmp[bitCtrl] = iVector[bitCtrl];

    for (unsigned char shiftCtrl = 0; shiftCtrl < nShifts; shiftCtrl++) {
        oVector[nBits - 1] = iVectorTmp[0];

        for (bitCtrl = 1; bitCtrl < nBits; bitCtrl++)
            oVector[bitCtrl - 1] = iVectorTmp[bitCtrl];

        for (bitCtrl = 0; bitCtrl < nBits; bitCtrl++)
            iVectorTmp[bitCtrl] = oVector[bitCtrl];
    }
};

void joinRL(_Bool* vector, unsigned char length, const _Bool* keyR, const _Bool* keyL) {
    for (int i = 0; i < ( length / 2 ); i++) {
        vector[i] = keyL[i];
        vector[i + (length / 2)] = keyR[i];
    }
}

void performPC2(const _Bool* key, const unsigned char* PC2, _Bool* newKey) {
    for (unsigned char i = 0; i < 48; i++)
        newKey[i] = key[PC2[i] - 1];
}

void performIP(const _Bool* message, const unsigned char* IP_, _Bool* newMessageR, _Bool* newMessageL) {
    _Bool newMessage[64];
    for (unsigned char i = 0; i < 64; i++)
        newMessage[i] = message[IP_[i] - 1];
    partitionRL(newMessage, 64, newMessageR, newMessageL);
}

void performIPInverse(const _Bool* PreCrypto, const unsigned char* IPInv, _Bool* Crypto) {
    for (unsigned char i = 0; i < 64; i++)
        Crypto[i] = PreCrypto[IPInv[i] - 1];
}

void doPermutationP(const _Bool* SmR, const unsigned char* P, _Bool* PmR) {
    for (unsigned char i = 0; i < 32; i++)
        PmR[i] = SmR[P[i] - 1];
}

void functionE(const _Bool* iVector, const unsigned char* EBitSelection, _Bool* oVector) {
    for (unsigned char i = 0; i < 48; i++)
        oVector[i] = iVector[EBitSelection[i] - 1];
}

void char2_Bool(unsigned char charVar, _Bool* boolVec, unsigned char nBits) {
    for (int i = 0; i < nBits; i++) {
        if ( charVar % 2 == 0)
            boolVec[nBits - i - 1] = 0;
        else
            boolVec[nBits - i - 1] = 1;

        charVar = (charVar - (charVar % 2)) / 2;
    }
}

void functionS(const _Bool* iVector, unsigned char S[][4][16], _Bool* oVector) {
    _Bool boolTmp[4] = {0};
    for (int i = 0; i < 8; i++) {
        // The first and last bits of B represent in base 2 a number in the decimal range 0 to 3 (or binary 00 to 11).
        unsigned char row = iVector[i * 6] * 2 + iVector[i * 6 + 5] * 1;
        unsigned char col = iVector[i * 6 + 1] * 8 + iVector[i * 6 + 2] * 4 + iVector[i * 6 + 3] * 2 + iVector[i * 6 + 4] * 1;
        unsigned char charTmp = S[i][row][col];
        char2_Bool(charTmp, boolTmp, 4);
        for (int j = 0; j < 4; j++)
            oVector[i * 4 + j] = boolTmp[j];
    }
}

void XOR(const _Bool* vector1, const _Bool* vector2, unsigned char nElements, _Bool* vectorRes) {
    for(int i = 0; i < nElements; i++)
        if (vector1[i] != vector2[i]) vectorRes[i] = 1;
        else vectorRes[i] = 0;
}

void functionF(const _Bool* mR, const _Bool* Key, const unsigned char* EBitSelection, unsigned char S[][4][16], const unsigned char* P, _Bool* outputF) {
    _Bool EmR[48] = {0}, KEmR[48] = {0}, SmR[32] = {0}, PmR[32] = {0};
    functionE(mR, EBitSelection, EmR);
    XOR(Key, EmR, 48, KEmR);
    functionS(KEmR, S, SmR);
    doPermutationP(SmR, P, PmR);
    memcpy(outputF, PmR, 32 * sizeof(PmR[0]));
}

void print_BoolVector(const _Bool* vector, unsigned char length) {
    for (int i = 0; i < length; i++)
        printf("%d", *(vector + i));
    printf("\n");
}

void print_HexVector(const unsigned char* vector, unsigned char length) {
    for (int i = 0; i < length; i++)
        printf("%0x", *(vector + i));
    printf("\n");
}


void vector2Hex(const _Bool* binaryArray, const unsigned char length, unsigned char* hexArray) {
    const unsigned char numBlocks = length / 4;

    for (unsigned char block = 0; block < numBlocks; block++) {
        unsigned char byte = 0;

        for (int i = 0; i < 4; i++)
            byte = (byte << 1) | (binaryArray[block * 4 + i] ? 1 : 0);

        hexArray[block] = byte;
    }
}
