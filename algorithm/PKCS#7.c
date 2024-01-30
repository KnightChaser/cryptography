// KnightChaser's style PKCS#7 padding implementation

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char BYTE;

void pkcs7Padding(BYTE *data, size_t dataLengthInByte, size_t blockSizeInByte) {
    size_t paddingSizeInByte = blockSizeInByte - (dataLengthInByte % blockSizeInByte);

    // If the length of data is divisible by the block size, no further actions are required.
    if (paddingSizeInByte == 0)
        return;

    // Conduct PKCS#7 padding
    for (size_t index = 0; index < paddingSizeInByte; index++)
        data[dataLengthInByte + index] = (BYTE)paddingSizeInByte;
}

void printBYTEDataInHexadecimal(BYTE *data, size_t dataLengthInByte) {
    for(size_t index = 0; index < dataLengthInByte; index++)
        printf("%02x", data[index]);
}

int main(void) {

    char* data = "PKCS#7_padding_ex";
    size_t blockSizeInByte = 32;      // Assume an environment for AES-256
    size_t blockSizeInByteAllocated = sizeof(BYTE) *  blockSizeInByte;

    BYTE *block = malloc(blockSizeInByteAllocated);
    memset(block, 0x00, blockSizeInByteAllocated);
    memcpy(block, data, strlen(data));

    printf("Original(string): %s\n", data);
    printf("Original(Hex)   : ");   printBYTEDataInHexadecimal(block, blockSizeInByteAllocated); printf("\n");

    pkcs7Padding(block, strlen(data), blockSizeInByte);
    printf("Padded  (Hex)   : ");   printBYTEDataInHexadecimal(block, blockSizeInByteAllocated); printf("\n");

    free(block);
    return 0;
}

// Example output)
// Original(string): PKCS#7_padding_ex
// Original(Hex)   : 504b435323375f70616464696e675f6578000000000000000000000000000000
// Padded  (Hex)   : 504b435323375f70616464696e675f65780f0f0f0f0f0f0f0f0f0f0f0f0f0f0f