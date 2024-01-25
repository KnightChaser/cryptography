// Salsa20 256-bits(32-bytes) key implementation
#include <stdint.h>
#include <stdio.h>

typedef uint32_t uint32;
typedef uint8_t uint8;

#define ROUNDS 20       // Compliance on Salsa20 specification

// Rotate Left (32-bit)
uint32 ROTL(uint32 value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

void salsa20QuarterRound(uint32 *a, uint32 *b, uint32 *c, uint32 *d) {
    *b ^= ROTL((*a + *d), 7);
    *c ^= ROTL((*b + *a), 9);
    *d ^= ROTL((*c + *b), 13);
    *a ^= ROTL((*d + *c), 18);
}

void salsa20Block(uint32 state[16]) {

    for (int index = 0; index < ROUNDS; index += 2) {
        // In case of odd round, execute the following 4 quarter rounds
        salsa20QuarterRound(&state[0], &state[4], &state[8], &state[12]);
        salsa20QuarterRound(&state[5], &state[9], &state[13], &state[1]);
        salsa20QuarterRound(&state[10], &state[14], &state[2], &state[6]);
        salsa20QuarterRound(&state[15], &state[3], &state[7], &state[11]);

        // In case of even round, execute the following 4 quarter rounds
        salsa20QuarterRound(&state[0], &state[1], &state[2], &state[3]);
        salsa20QuarterRound(&state[5], &state[6], &state[7], &state[4]);
        salsa20QuarterRound(&state[10], &state[11], &state[8], &state[9]);
        salsa20QuarterRound(&state[15], &state[12], &state[13], &state[14]);
    }
}

void salsa20Encrypt(uint8 *plaintext, uint8 *ciphertext, uint32 key[8], uint32 nonce[2]) {
    uint32 state[16];
    
    // Initial Salsa20 states will look like
    //    0      1       2       3
    // ["expa"][key]   [key]   [key]      A
    // [key]   ["nd 3"][Nonce] [Nonce]    B
    // [Pos]   [Pos]   ["2 by"][key]      C
    // [key]   [key]   [key]   ["te k"]   D

    // Setting up initial state; Constants (32bytes/256bits key length)
    state[0] = 0x61707865;      // "expa"
    state[5] = 0x3320646e;      // "nd 3"
    state[10] = 0x79622d32;     // "2-by"
    state[15] = 0x6b206574;     // "te k"

    // Setting up initial state; Key
    state[1] = key[0];
    state[2] = key[1];
    state[3] = key[2];
    state[4] = key[3];
    state[11] = key[4];
    state[12] = key[5];
    state[13] = key[6];
    state[14] = key[7];

    // Setting up initial state; Nonce
    state[6] = nonce[0];
    state[7] = nonce[1];

    // Setting up initial state; Stream positions
    state[8] = 0x00;
    state[9] = 0x00;

    // Setting up initial state; Block
    salsa20Block(state);

    // XOR the input with the generated keystream to produce the output (byte by byte)
    for (int index = 0; index < 64; ++index) {
        ciphertext[index] = plaintext[index] ^ ((uint8 *)state)[index];
    }
}

void salsa20Decrypt(uint8 *ciphertext, uint8 *plaintext, uint32 key[8], uint32 nonce[2]) {
    // Salsa20 is symmetric, so encryption and decryption are the same
    salsa20Encrypt(ciphertext, plaintext, key, nonce);
}

int main(int argc, char* argv[]) {
    uint8 plaintext[64] = "$alsa20$al5asaucewww";
    uint8 ciphertext[64];
    uint32 key[8]   = {0x00000000, 0x12345678, 0xABCDEEEE, 0xCAFECAFE, 0xBEEF7777, 0x47479191, 0x40A8C7EE, 0xAB817777};
    uint32 nonce[2] = {0x0000CAFE, 0xFADE0001};

    printf("Original:  %s\n", plaintext);
    printf("key:       ");
    for(int k = 0; k < 8; k++)
        printf("%x", key[k]);
    printf("\n");

    // Salsa20 Encryption
    salsa20Encrypt(plaintext, ciphertext, key, nonce);
    printf("Encrypted: ");
    for(int k = 0; k < 64; k++)
        printf("%02x", ciphertext[k]);
    printf("\n");

    // Salsa20 Decryption
    salsa20Decrypt(ciphertext, plaintext, key, nonce);
    printf("Decrypted: %s\n", plaintext);

    return 0;
}
