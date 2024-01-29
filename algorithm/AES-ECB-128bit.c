// AES-ECB, 128-bit key length
// KnightChaser's style implementation in C language

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LENGTH_OF_KEY 4             // key length
#define NUMBER_OF_STATE_WORDS 4     // word byte of aesState 
#define NUMBER_OF_ROUND 10          // round number

typedef uint8_t BYTE;

BYTE aesState[4][4] = {0,};                        // 16-byte state for saving intermediary status during encryption
BYTE aesRoundKey[240] = {0, };                     // To save keys for AES round
BYTE aesCipherKey[16] = {0x77, 0xCF, 0x41, 0x90,
                         0x68, 0x31, 0x22, 0x45,
                         0x99, 0x68, 0x49, 0x55,
                         0x31, 0x0D, 0xFF, 0xAF};  // A key for AES encryption&decryption
                                                   // 16 byte * 8 bit = 128 bit length key

// Precalculated S-Box
static const BYTE aesSbox[16 * 16] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,  //  0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,  //  1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,  //  2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,  //  3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,  //  4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,  //  5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,  //  6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,  //  7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,  //  8
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,  //  9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,  //  A
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,  //  B
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,  //  C
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,  //  D
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,  //  E
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}; //  F

// Precalculated inversed S-box
static const BYTE aesInversedSbox[16 * 16] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,  //  0
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,  //  1
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,  //  2
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,  //  3
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,  //  4
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,  //  5
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,  //  6
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,  //  7
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,  //  8
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,  //  9
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,  //  A
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,  //  B
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,  //  C
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,  //  D
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,  //  E
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D   //  F
};

// A constant values used at each AES round
static const BYTE aesRoundConstant[16 * 16] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,  //  0
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,  //  1
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,  //  2
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,  //  3
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,  //  4
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,  //  5
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,  //  6
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,  //  7
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,  //  8
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,  //  9
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,  //  A
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,  //  B
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,  //  C
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,  //  D
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,  //  E
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d   //  F
};

// AES SubByte() procedure, substituting byte by byte
void aesSubBytes() {
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            aesState[x][y] = aesSbox[aesState[x][y]];
        }
    }
}

// AES InversedSubByte() procedure, substituting byte by byte
void aesInversedSubBytes() {
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            aesState[x][y] = aesInversedSbox[aesState[x][y]];
        }
    }
}

// AES ShiftRow() operation, conducting cyclic left shift operation with the state column by column
void aesShiftRows() {
    BYTE tempByte = 0x00;

    // No shift for the first column

    // shift 1 byte for the second column
    tempByte       = aesState[1][0];
    aesState[1][0] = aesState[1][1];
    aesState[1][1] = aesState[1][2];
    aesState[1][2] = aesState[1][3];
    aesState[1][3] = tempByte;

    // shift 2 bytes for the third column
    tempByte       = aesState[2][0];
    aesState[2][0] = aesState[2][2];
    aesState[2][2] = tempByte;
    tempByte       = aesState[2][1];
    aesState[2][1] = aesState[2][3];
    aesState[2][3] = tempByte;

    // shift 3 bytes for the fourth column
    tempByte       = aesState[3][0];
    aesState[3][0] = aesState[3][3];
    aesState[3][3] = aesState[3][2];
    aesState[3][2] = aesState[3][1];
    aesState[3][1] = tempByte;
}

// AES InvShiftRow() operation, conducting cyclic right shift operation with the state column by column
void aesInversedShiftRows() {
    BYTE tempByte = 0x00;

    // No shift for the first column

    // Shift 1 bytes for the second column
    tempByte       = aesState[1][3];
    aesState[1][3] = aesState[1][2];
    aesState[1][2] = aesState[1][1];
    aesState[1][1] = aesState[1][0];
    aesState[1][0] = tempByte;
 
    // Shift 2 bytes for the third column
    tempByte       = aesState[2][0];
    aesState[2][0] = aesState[2][2];
    aesState[2][2] = tempByte;
    tempByte       = aesState[2][1];
    aesState[2][1] = aesState[2][3];
    aesState[2][3] = tempByte;
 
    // Shift 3 bytes for the fourth column
    tempByte       = aesState[3][0];
    aesState[3][0] = aesState[3][1];
    aesState[3][1] = aesState[3][2];
    aesState[3][2] = aesState[3][3];
    aesState[3][3] = tempByte;
}

// The multiplyInGF function performs multiplication in the Galois Field (GF).
// It multiplies two values, 'b' and 'n', based on the specified polynomial.
BYTE multiplyInGF(BYTE b, BYTE n) {
    BYTE result = 0;
    BYTE mask = 0x01;

    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
        if (n & mask)
            result ^= b;

        if (b & 0x80)
            b = (b << 1) ^ 0x1B; // Reducing polynomial in GF(2^8)
        else
            b <<= 1;

        mask <<= 1;
    }

    return result;
}


// Each byte of a column is mapped into a new value that is a function of all 4 bytes in that column.
void aesMixColumns() {
	int i, j, k;
	BYTE aesMixColumnMatrix[4][4] = {0x2, 0x3, 0x1, 0x1,
                                     	 0x1, 0x2, 0x3, 0x1,
                                     	 0x1, 0x1, 0x2, 0x3,
                                     	 0x3, 0x1, 0x1, 0x2};

	for (i = 0; i < 4; i++) {
		BYTE tempByte[4] = { 0, };

		for (j = 0; j < 4; j++)
			for (k = 0; k < 4; k++)
				tempByte[j] ^= multiplyInGF(aesState[k][i], aesMixColumnMatrix[j][k]);

		aesState[0][i] = tempByte[0];
		aesState[1][i] = tempByte[1];
		aesState[2][i] = tempByte[2];
		aesState[3][i] = tempByte[3];
	}
}

void aesInversedMixColumns() {
    int i, j, k;
    BYTE aesInversedMixColumnMatrix[4][4] = {0xE, 0xB, 0xD, 0x9,
                                             0x9, 0xE, 0xB, 0xD,
                                             0xD, 0x9, 0xE, 0xB,
                                             0xB, 0xD, 0x9, 0xE};

    for (i = 0; i < 4; i++) {
        BYTE tempByte[4] = { 0, };

        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                tempByte[j] ^= multiplyInGF(aesState[k][i], aesInversedMixColumnMatrix[j][k]);

        aesState[0][i] = tempByte[0];
        aesState[1][i] = tempByte[1];
        aesState[2][i] = tempByte[2];
        aesState[3][i] = tempByte[3];
    }
}

// XOR bit by bit with 128-bit aesState array and 128-bit aesRoundKey
void aesAddRoundKey(int round) {
    for (int x = 0; x < 4; x++) {
        for (int y = 0; y < 4; y++) {
            aesState[y][x] ^= aesRoundKey[round * 4 * 4 + x * 4 + y];
        }
    }
}

// AES Key Expansion procedure
// Based on the previous aesRoundKey, create keys for every AES round
void aesKeyExpansion() {

    int i;
    BYTE tempByteArray[4];

    // Initialization: Copy the initial key (aesCipherKey) to the first round key
    for (i = 0; i < 4; i++) {
        aesRoundKey[i * 4]     = aesCipherKey[i * 4];
        aesRoundKey[i * 4 + 1] = aesCipherKey[i * 4 + 1];
        aesRoundKey[i * 4 + 2] = aesCipherKey[i * 4 + 2];
        aesRoundKey[i * 4 + 3] = aesCipherKey[i * 4 + 3];
    }

    // Key expansion for subsequent rounds
    for (i = 4; i < 44; i++) {
        // Temporarily store the previous round key
        tempByteArray[0] = aesRoundKey[(i - 1) * 4 + 0];
        tempByteArray[1] = aesRoundKey[(i - 1) * 4 + 1];
        tempByteArray[2] = aesRoundKey[(i - 1) * 4 + 2];
        tempByteArray[3] = aesRoundKey[(i - 1) * 4 + 3];

        // Perform operations based on the current round index
        // if (i mod 4 == 0), then temp = SubWord(RotWord(temp)) XOR aesRoundConstant[i/4];
        if (i % 4 == 0) {
            // RotWord: Perform cyclic movement of bytes in a word
            // SubWord: Substitute each byte with the value from the S-box
            tempByteArray[0] = aesSbox[tempByteArray[0]];
            tempByteArray[1] = aesSbox[tempByteArray[1]];
            tempByteArray[2] = aesSbox[tempByteArray[2]];
            tempByteArray[3] = aesSbox[tempByteArray[3]];

            // XOR the first byte with the round constant
            tempByteArray[0] ^= aesRoundConstant[i / 4];
        }

        // Calculate the current round key
        // Based on the previous AES round key, calculate the current AES round key
        aesRoundKey[i * 4 + 0] = aesRoundKey[(i - 4) * 4 + 0] ^ tempByteArray[0];
        aesRoundKey[i * 4 + 1] = aesRoundKey[(i - 4) * 4 + 1] ^ tempByteArray[1];
        aesRoundKey[i * 4 + 2] = aesRoundKey[(i - 4) * 4 + 2] ^ tempByteArray[2];
        aesRoundKey[i * 4 + 3] = aesRoundKey[(i - 4) * 4 + 3] ^ tempByteArray[3];
    }
}

// AES Encryption procedure with 128-bit length key
void aes128Encrypt(BYTE* plaintext, BYTE *ciphertext) {
    // Copy the input plaintext into the aesState matrix
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            aesState[y][x] = plaintext[x * 4 + y];
        }
    }

    // Initial round key addition
    aesAddRoundKey(0x00);

    // Main encryption rounds
    for(int round = 1; round < NUMBER_OF_ROUND; round++) {
        // SubBytes: Substitute each byte with the value from the S-box
        aesSubBytes();

        // ShiftRows: Perform cyclic left shifts on each row
        aesShiftRows();

        // MixColumns: Combine bytes of each column using matrix multiplication
        aesMixColumns();

        // AddRoundKey: XOR the state with the round key
        aesAddRoundKey(round);
    }

    // Final round (without MixColumns)
    aesSubBytes();
    aesShiftRows();
    aesAddRoundKey(NUMBER_OF_ROUND);  // Note: No MixColumns in the final round

    // Copy the final state to the ciphertext
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            ciphertext[x * 4 + y] = aesState[y][x];
        }
    }
}


// AES Decryption procedure with 128-bit length key
void aes128Decrypt(BYTE *ciphertext, BYTE *plaintext) {
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            aesState[y][x] = ciphertext[x * 4 + y];
        }
    }

    aesAddRoundKey(NUMBER_OF_ROUND);
    for(int round = NUMBER_OF_ROUND - 1; round > 0; round--) {
        aesInversedShiftRows();
        aesInversedSubBytes();
        aesAddRoundKey(round);
        aesInversedMixColumns();
    }
    aesInversedShiftRows();
    aesInversedSubBytes();
    aesAddRoundKey(0x00);
    
    for(int x = 0; x < 4; x++) {
        for(int y = 0; y < 4; y++) {
            plaintext[x * 4 + y] = aesState[y][x];
        }
    }
}

void printDataInHexadecimal(BYTE* data, unsigned int dataLengthByte) {
    for (int byte; byte < dataLengthByte; byte++) {
        printf("%02x", data[byte]);
    }
}

void printStringInByte(BYTE* data, unsigned int dataLengthByte) {
    for (int byte; byte < dataLengthByte; byte++) {
        printf("%c", data[byte]);
    }
}

#define BUFFER_LENGTH_BYTE 128

int main(int argc, char* argv[]) {

    printf("=== KnightChaser's AES(ECB/128 bit key) playground ===\n");
    
    // Original plaintext
    BYTE plaintext[BUFFER_LENGTH_BYTE] = "AES(Advanced Encryption Standard) is super duper uwuper strong! Yay!! >_<";
    BYTE ciphertext[BUFFER_LENGTH_BYTE];
    BYTE decryptedText[BUFFER_LENGTH_BYTE];
    
    // Key initialization
    aesKeyExpansion();
    
    // Show plaintext (original)
    printf("Original Plaintext: %s\n", plaintext);

    // Show key
    printf("Key: ");        
    printDataInHexadecimal(aesCipherKey, 16);   
    printf("\n\n");

    // Encrypt and show ciphertext block by block
    // Block size: 128 bit = 16 byte(16 characters in ASCII)
    printf("Encrypted Blocks:\n");
    for (int block = 0; block < BUFFER_LENGTH_BYTE; block += 16) {
        aes128Encrypt(plaintext + block, ciphertext + block);
        printf("Block #%d: ", (block / 16) + 1);
        printDataInHexadecimal(ciphertext + block, 16);
        printf("\n");
    }

    // Decrypt and show plaintext block by block
    printf("\nDecrypted Blocks:\n");
    for (int block = 0; block < BUFFER_LENGTH_BYTE; block += 16) {
        aes128Decrypt(ciphertext + block, decryptedText + block);
        printf("Block #%d: ", (block / 16) + 1);
        printStringInByte(decryptedText + block, 16);
        printf("\n");
    }

    printf("\nDecrypted plaintext: %s\n", decryptedText);


    return 0;
}
