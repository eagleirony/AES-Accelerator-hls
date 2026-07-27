// Test Case 1: AES-128 from FIPS-197 Appendix C.1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>

#include "../code/kernel/keyExpandedOptimisation/aes.h"
const uint8_t key128[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
const uint8_t plaintext128[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
const uint8_t ciphertext128[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                 0x19, 0x6a, 0x0b, 0x32};
#define KEYSIZEBYTES 32
int main() {
    for (int j = 0; j < 42;j++) {
    uint8_t ciphertextOut[16];
    uint8_t ciphertextIn[16];
    uint8_t plaintextIn[16];
    uint8_t keyIn[KEYSIZEBYTES];
    for (int i = 0; i < 16; i++) {
        plaintextIn[i] = rand() & 0xFF;

    }
    for (int i = 0; i < KEYSIZEBYTES;i++) {
        keyIn[i] = rand() & 0xFF;
    }
    AES_KEY key;
    AES_set_encrypt_key(keyIn, KEYSIZEBYTES*8, &key);
    AES_ecb_encrypt(plaintextIn, ciphertextIn, &key, 0);
    aes_encrypt(plaintextIn, ciphertextOut, keyIn);
    for (int i = 0; i < 16; i++) {
        if (ciphertextOut[i] != ciphertextIn[i]) {
            printf("Ah Shit\n");
        }
    }
}
}
