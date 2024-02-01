// KnightChaser's style simple Diffie-Hellman implementation
#include <stdio.h>

typedef unsigned long long int ULL; 

// Calculate g^x mod p efficiently
ULL modexp(ULL g, ULL x, ULL p) {
    ULL result = 1;
    while (x > 0) {
        if (x & 1) {
            // If the least significant bit of x is 1, multiply the result by g and take the modulo p
            result = (result * g) % p;
        }
        g = (g * g) % p;
        x >>= 1;  // Use bitwise right shift instead of x = x / 2
    }
    return result;
}

int main(void) {
    // ULL p, g, a, b, A, B, s1, s2;
    ULL p, g;
    ULL privateKeyA, privateKeyB;
    ULL publicKeyA, publicKeyB;
    ULL secretKeyA, secretKeyB;

    p = 23; // Prime number
    g = 5;  // Primitive root of p

    privateKeyA = 6; // Private key of A
    privateKeyB = 15; // Private key of B

    publicKeyA = modexp(g, privateKeyA, p); // Public key of A
    publicKeyB = modexp(g, privateKeyB, p); // Public key of B
    printf("Public key of A(= g^a mod p): %llu\n", publicKeyA);
    printf("Public key of B(= g^b mod p): %llu\n", publicKeyB);

    secretKeyA = modexp(publicKeyB, privateKeyA, p); // Secret key of A
    secretKeyB = modexp(publicKeyA, privateKeyB, p); // Secret key of B

    if (secretKeyA == secretKeyB) {
        // Now both A and B have the same secret key
        printf("Secret key of A(= B^a mod p): %llu\n", secretKeyA);
        printf("Secret key of B(= A^b mod p): %llu\n", secretKeyB);
        printf("** Secret keys match **\n");
    } else {
        printf("Secret keys do not match\n");
        return -1;
    }

    return 0;
}