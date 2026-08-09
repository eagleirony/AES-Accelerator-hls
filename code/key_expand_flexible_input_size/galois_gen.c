#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

//clang galois_gen.c -o out -D B_VAL=3

// Galois Field (GF(2^8)) constants for the MixColumns step.
#define GF_REDUCING_POLYNOMIAL \
    0x1B  // Irreducible polynomial for AES: x^8 + x^4 + x^3 + x + 1
#define GF_MSB_MASK 0x80

#define BITS_PER_BYTE 8
#ifndef B_VAL
#define B_VAL 2 //Change this to modify the generated field
#endif

static uint8_t galois_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < BITS_PER_BYTE; i++) {
        if (b & 1) {
            p ^= a;
        }

        uint8_t hi_bit_set = a & GF_MSB_MASK;
        a <<= 1;

        if (hi_bit_set) {
            a ^= GF_REDUCING_POLYNOMIAL;
        }

        b >>= 1;
    }
    return p;
}


int main() {
    char filename[256];
    snprintf(filename, 256, "galois%d.txt", B_VAL);
    FILE *output = fopen(filename, "w");
    fprintf(output, "static const uint8_t galois%d[256] = {\n", B_VAL);
    for (uint16_t i = 0; i < 256; i++) {
        uint8_t outputVal = galois_mul(i, B_VAL);
        fprintf(output, "%#x,\n", outputVal);
    }
    fprintf(output, "};\n");
    fclose(output);
}