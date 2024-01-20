// LCG(Linear Congruential Generator) demonstration
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// parameters
#define MULTIPLIER 1664525
#define INCREMENT 1013904223
#define MODULUS 4294967296  // 2^32

// Function to generate a random number using LCG
// X_(n+1) = (a X_n + c) mod m, (n ≥ 0)
unsigned int generateRandomNumber(unsigned int* seed) {
    *seed = (*seed * MULTIPLIER + INCREMENT) % MODULUS;
    return *seed;
}

int main() {
    // Seed the generator with the current time
    unsigned int seed = (unsigned int)time(NULL);

    // Generate and print 10 random numbers
    for (int i = 0; i < 10; ++i) {
        unsigned int randomNumber = generateRandomNumber(&seed);
        printf("%u\n", randomNumber);
    }

    return 0;
}
