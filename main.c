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

void tripleDesEncryption(const _Bool*, const _Bool [16][48], const _Bool [16][48], const _Bool [16][48], _Bool*);

int main(void) {
    const _Bool message[64] = {
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1,
        0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1
    };
    const _Bool key1[64] = {
        0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1,
        0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1
    };
    const _Bool key2[64] = {
        1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
        1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1
    };
    const _Bool key3[64] = {
        0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0,
        1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0
    };

    _Bool subkeys1[16][48];
    _Bool subkeys2[16][48];
    _Bool subkeys3[16][48];
    createSubkeys(key1, subkeys1);
    createSubkeys(key2, subkeys2);
    createSubkeys(key3, subkeys3);

    _Bool reversedSubkeys1[16][48];
    _Bool reversedSubkeys2[16][48];
    _Bool reversedSubkeys3[16][48];
    reverseSubkeys(subkeys1, reversedSubkeys1);
    reverseSubkeys(subkeys2, reversedSubkeys2);
    reverseSubkeys(subkeys3, reversedSubkeys3);

    // SINGLE DES ENCRYPTION & DECRYPTION
    printf("SINGLE DES OPERATION:\n");
    _Bool desCipher[64];
    desEncryption(message, subkeys1, desCipher);

    unsigned char messageHex[16];
    vector2Hex(message, 64, messageHex);
    printf("HEX MESSAGE: ");
    print_HexVector(messageHex, 16);

    unsigned char desCipherHex[16];
    vector2Hex(desCipher, 64, desCipherHex);
    printf("HEX CIPHER: ");
    print_HexVector(desCipherHex, 16);

    _Bool desDecrypt[64];
    desEncryption(desCipher, reversedSubkeys1, desDecrypt);

    unsigned char desDecryptHex[16];
    vector2Hex(desDecrypt, 64, desDecryptHex);
    printf("HEX DECRYPTED CIPHER: ");
    print_HexVector(desDecryptHex, 16);

    // TRIPLE DES ENCRYPTION & DECRYPTION - ONE KEY
    printf("\nTRIPLE DES OPERATION (1 KEY):\n");
    _Bool des3Cipher1[64];
    tripleDesEncryption(message, subkeys1, reversedSubkeys1, subkeys1, des3Cipher1);

    printf("HEX MESSAGE: ");
    print_HexVector(messageHex, 16);

    unsigned char des3CipherHex1[16];
    vector2Hex(des3Cipher1, 64, des3CipherHex1);
    printf("HEX CIPHER: ");
    print_HexVector(des3CipherHex1, 16);

    _Bool des3Decrypt1[64];
    tripleDesEncryption(des3Cipher1, reversedSubkeys1, subkeys1, reversedSubkeys1, des3Decrypt1);

    unsigned char des3DecryptHex1[16];
    vector2Hex(des3Decrypt1, 64, des3DecryptHex1);
    printf("HEX DECRYPTED CIPHER: ");
    print_HexVector(des3DecryptHex1, 16);

    // TRIPLE DES ENCRYPTION & DECRYPTION - TWO KEYS
    printf("\nTRIPLE DES OPERATION (2 KEYS):\n");
    _Bool des3Cipher2[64];
    tripleDesEncryption(message, subkeys1, reversedSubkeys2, subkeys1, des3Cipher2);

    printf("HEX MESSAGE: ");
    print_HexVector(messageHex, 16);

    unsigned char des3CipherHex2[16];
    vector2Hex(des3Cipher2, 64, des3CipherHex2);
    printf("HEX CIPHER: ");
    print_HexVector(des3CipherHex2, 16);

    _Bool des3Decrypt2[64];
    tripleDesEncryption(des3Cipher2, reversedSubkeys1, subkeys2, reversedSubkeys1, des3Decrypt2);

    unsigned char des3DecryptHex2[16];
    vector2Hex(des3Decrypt2, 64, des3DecryptHex2);
    printf("HEX DECRYPTED CIPHER: ");
    print_HexVector(des3DecryptHex2, 16);

    // TRIPLE DES ENCRYPTION & DECRYPTION - THREE KEYS
    printf("\nTRIPLE DES OPERATION (3 KEYS):\n");
    _Bool des3Cipher3[64];
    tripleDesEncryption(message, subkeys1, reversedSubkeys2, subkeys3, des3Cipher3);

    printf("HEX MESSAGE: ");
    print_HexVector(messageHex, 16);

    unsigned char des3CipherHex3[16];
    vector2Hex(des3Cipher3, 64, des3CipherHex3);
    printf("HEX CIPHER: ");
    print_HexVector(des3CipherHex3, 16);

    _Bool des3Decrypt3[64];
    tripleDesEncryption(des3Cipher3, reversedSubkeys3, subkeys2, reversedSubkeys1, des3Decrypt3);

    unsigned char des3DecryptHex3[16];
    vector2Hex(des3Decrypt3, 64, des3DecryptHex3);
    printf("HEX DECRYPTED CIPHER: ");
    print_HexVector(des3DecryptHex3, 16);

    return 0;
}

/**
 * Funkcja tworząca podklucze z klucza szyfrującego.
 *
 * @param key Klucz szyfrowania.
 * @param subkeys Podklucze wyjściowe.
 */
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

/**
 * Funkcja zamieniająca kolejność podkluczy.
 *
 * @param originalSubkeys Podklucze wejściowe.
 * @param reversedSubkeys Podklucze wyjściowe.
 */
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

/**
 * Funkcja wykonujaca szyfrowanie DES (Data Encryption Standard).
 * Może zostać również wykorzystana jako funkcja deszyfrująca jeśli podklucze
 * będą w odwrotnej kolejności względem podkluczy szyfrujących.
 *
 * @param message Wiadomość do zaszyfrowania.
 * @param subkeys Podklucze szyfrujące.
 * @param cipher Wiadomość zaszyfrowana.
 */
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

/**
 * Funkcja wykonująca potrójne szyfrowanie DES.
 * Może zostać również wykorzystana jako funkcja deszyfrująca jeśli podklucze
 * będą w odwrotnej kolejności względem podkluczy szyfrujących.
 * W przypadku deszyfrownia kolejność podania kluczy również musi być odwrotna.
 *
 * @param message Wiadomość do zaszyfrowania.
 * @param subkeys1 Podklucze wykorzystane w pierwszym szyfrowaniu.
 * @param subkeys2 Podklucze wykorzystane w deszyfrowaniu.
 * @param subkeys3 Podklucze wykorzystane w ostatnim szyfrowaniu.
 * @param oCipher Wiadomość zaszyfrowana.
 */
void tripleDesEncryption(const _Bool* message, const _Bool subkeys1[16][48], const _Bool subkeys2[16][48], const _Bool subkeys3[16][48], _Bool* oCipher) {
    _Bool cipher[64];
    _Bool decryptCipher[64];

    desEncryption(message, subkeys1, cipher);
    desEncryption(cipher, subkeys2, decryptCipher);
    desEncryption(decryptCipher, subkeys3, oCipher);
}