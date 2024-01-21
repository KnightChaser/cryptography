// Blum-Blum-Shub PRNG(Pseudo Random Number Generator) implementation
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <inttypes.h>
#define UINT64 uint64_t

// Function to calculate the greatest common divisor (GCD)
UINT64 gcd(UINT64 a, UINT64 b) {
    while (b != 0) {
        UINT64 temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to calculate the modular square
UINT64 mod_square(UINT64 x, UINT64 n) {
    return (x * x) % n;
}

// Blum Blum Shub PRNG function
UINT64 BBSPRNG(UINT64 seed, UINT64 n, UINT64 iterations) {
    UINT64 x = (UINT64)pow(seed, 2) % n;
    for (UINT64 sequence = 1; sequence < iterations; sequence++)
        x = mod_square(x, n);
    return x;
}

int main(void) {
    // Choose two large primes p and q such that p ≡ 3 (mod 4) and q ≡ 3 (mod 4)
    UINT64 p = 499, q = 547;
    
    // Calculate n = p * q
    UINT64 n = p * q;

    // Choose a seed (must be relatively prime to n)
    UINT64 seed = 123;

    // Calculate the initial state x0 = seed^2 mod n
    UINT64 x0 = (UINT64)pow(seed, 2) % n;

    // Number of iterations
    uint64_t iterations = 25;

    // Generate pseudo-random numbers using BBS
    for (UINT64 sequence = 0; sequence < iterations; sequence++)
        printf("[%lu] => %lu\n", sequence, BBSPRNG(x0, n, sequence));

    return 0;
}

// [0] => 152027
// [1] => 152027
// [2] => 186407
// [3] => 106843
// [4] => 259236
// [5] => 91472
// [6] => 25522
// [7] => 106626
// [8] => 65520
// [9] => 138569
// [10] => 216023
// [11] => 253931
// [12] => 173759
// [13] => 39892
// [14] => 55674
// [15] => 212961
// [16] => 154759
// [17] => 87096
// [18] => 76393
// [19] => 155309
// [20] => 28871
// [21] => 209132
// [22] => 115375
// [23] => 18721
// [24] => 4189
