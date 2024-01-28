#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char BYTE;

void swapByte(BYTE *first, BYTE *second) {
    BYTE temporary = *first;
    *first = *second;
    *second = temporary;
}

void rc4Encrypt(char *plaintext, char *key, char *ciphertext) {
    BYTE S[256];
    BYTE T[256];

    // Initialization; save 0, 1, 2, ..., 255 to S
    for (int index = 0; index < 256; index++) {
        S[index] = index;
        T[index] = key[index % strlen(key)];
    }

    int i = 0, j = 0, t = 0;
    // With using T, create an initial permutation of S
    for (int index = 0; index < 256; index++) {
        j = (j + S[index] + T[index]) % 256;
        swapByte(&S[index], &S[j]); // substitution
    }

    BYTE RC4StreamByte;
    // RC4 bit stream generation
    for (int counter = 0; counter < strlen(plaintext); counter++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swapByte(&S[i], &S[j]);

        t = (S[i] + S[j]) % 256;
        RC4StreamByte = S[t];

        // encryption
        ciphertext[counter] = plaintext[counter] ^ S[RC4StreamByte];
    }

    // Null terminating
    ciphertext[strlen(plaintext)] = '\0';
}

void rc4Decrypt(char *ciphertext, char *key, char *decryptedtext) {
    // Decryption is the same as encryption in the case of RC4
    rc4Encrypt(ciphertext, key, decryptedtext);
}

int main(int argc, char* argv[]) {
    char key[] = "3ncr4p7k3y";                                                              // key
    char plaintext[] = "RC4 is a well-known stream encryption system developed in 1987.";   // plaintext
    char ciphertext[strlen(plaintext) + 1];
    printf("Original: %s\n", plaintext);

    // Encryption
    rc4Encrypt(plaintext, key, ciphertext);
    printf("Encrypted: %s\n", ciphertext);

    char decryptedtext[strlen(plaintext) + 1];

    // Decryption
    rc4Decrypt(ciphertext, key, decryptedtext);
    printf("Decrypted: %s\n", decryptedtext);

    return 0;
}
