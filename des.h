//
// Created by Szymon on 1/11/2025.
//

#ifndef DES_H
#define DES_H

void performPC1(const _Bool*, const unsigned char*, _Bool*);
void partitionRL(const _Bool*, unsigned char, _Bool*, _Bool*);
void shift2Left(const _Bool*, unsigned char, _Bool*);
void joinRL(_Bool*, unsigned char, const _Bool*, const _Bool*);
void performPC2(const _Bool*, const unsigned char*, _Bool*);
void performIP(const _Bool*, const unsigned char*, _Bool*, _Bool*);
void performIPInverse(const _Bool*, const unsigned char*, _Bool*);
void XOR(const _Bool*, const _Bool*, unsigned char, _Bool*);
void functionF(const _Bool* mR, const _Bool* Key, const unsigned char* EBitSelection, unsigned char S[][4][16], const unsigned char* P, _Bool* FOutput);

void print_BoolVector(const _Bool*, unsigned char);
void print_HexVector(const unsigned char*, unsigned char);
void vector2Hex(const _Bool*, unsigned char, unsigned char*);

#endif //DES_H
