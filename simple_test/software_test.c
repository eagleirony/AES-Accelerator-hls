// Test Case 1: AES-128 from FIPS-197 Appendix C.1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>

#include "../code/kernel/keyExpandedOptimisation/aes.h"
#define KEYSIZEBYTES 24
int main() {
    srand(time(NULL));
    for (int j = 0; j < 42;j++) {
    uint8_t ciphertextOut[16];
    uint8_t ciphertextIn[16];
    uint8_t plaintextIn[16];
    uint8_t keyIn[KEYSIZEBYTES];
    int inputlen = 16;
    int outputlen;
    int templen = 0;
    for (int i = 0; i < 16; i++) {
        plaintextIn[i] = rand() & 0xFF;
    }
    for (int i = 0; i < KEYSIZEBYTES;i++) {
        keyIn[i] = rand() & 0xFF;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, keyIn, NULL);
    EVP_EncryptUpdate(ctx, ciphertextIn, &outputlen, plaintextIn, inputlen);
    EVP_EncryptFinal_ex(ctx, ciphertextIn+outputlen, &templen);
    EVP_CIPHER_CTX_free(ctx);
    aes_encrypt(plaintextIn, ciphertextOut, keyIn);
    for (int i = 0; i < 16; i++) {
        if (ciphertextOut[i] != ciphertextIn[i]) {
            printf("%x : %x\n", ciphertextOut[i], ciphertextIn[i]);
        }
    }
}
}
