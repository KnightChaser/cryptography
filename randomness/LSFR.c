// PRNG with LFSR(Left Feedback Shift Register)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 8-bit LFSR parameters
#define LFSR_SIZE 8
#define FEEDBACK_MASK 0b10000001  // Feedback mask, tap positions marked with '1'

// Function to generate a random number using 8-bit LFSR
unsigned char LFSRrandomNumberGenerator(unsigned char* lfsr) {
    // XOR the feedback bits and rotating shift
    unsigned char feedback = ((*lfsr) & FEEDBACK_MASK) & 1;
    *lfsr >>= 1;
    *lfsr |= (feedback << (LFSR_SIZE - 1));

    return *lfsr;
}

int main() {
    // Seed the LFSR with the current time
    unsigned char lfsr = (unsigned char)time(NULL);

    for (int i = 0; i < 10; i++)
        printf("%u\n", (unsigned char)LFSRrandomNumberGenerator(&lfsr));
        
    return 0;
}
