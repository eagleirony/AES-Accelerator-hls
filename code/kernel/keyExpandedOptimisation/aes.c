/**
 * @file aes.c
 * @brief An implementation of the AES (Rijndael) algorithm.
 *
 * @details This file contains the core implementation of the AES encryption
 * and decryption routines. It is designed to be self-contained and easy to
 * integrate. The state is handled in a column-major format consistent with
 * the FIPS-197 specification.
 */

/*
 * Reference code from https://github.com/m3y54m/aes-in-c/tree/main
 */

#include "aes.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Internal constants for the AES implementation.
#define BITS_PER_BYTE 8
#define WORD_SIZE 4


// Galois Field (GF(2^8)) constants for the MixColumns step.
#define GF_REDUCING_POLYNOMIAL \
    0x1B  // Irreducible polynomial for AES: x^8 + x^4 + x^3 + x + 1
#define GF_MSB_MASK 0x80

/* --------------------------------------------------------------------------
 * S-Box and Inverse S-Box Lookup Tables
 * -------------------------------------------------------------------------- */

//! The AES Substitution Box (S-Box)
static const uint8_t sbox[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C
    // D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};  // F

//! The Round Constant (Rcon) table used in the key schedule.
static const uint8_t rcon[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                               0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
                               0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
                               0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39};

static void word_rotate_left(uint8_t * word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

static void key_schedule_core(uint8_t * word, uint8_t iteration) {
    word_rotate_left(word);

    for (uint8_t i = 0; i < WORD_SIZE; ++i) {
        word[i] = sbox[word[i]];
    }
    word[0] ^= rcon[iteration];
}


//This function keeps the key buffer up to date by modifying the section for the upcoming round
//It also moves the pointer round_key to the start of the 128 byte section needed
static void get_round_key(uint8_t *key, uint16_t round) {
    size_t current_size = round * AES_BLOCK_SIZE;
    uint8_t rcon_iteration = current_size / AES_KEY_SIZE;
    uint8_t temp_word[WORD_SIZE];
    for (size_t i = 0; i < AES_BLOCK_SIZE; i+=WORD_SIZE) {
        if (current_size < AES_KEY_SIZE) {
            current_size+=WORD_SIZE;
            continue;
        }
        for (size_t i = 0; i < WORD_SIZE; i++) {
            temp_word[i] = key[(current_size - WORD_SIZE + i)%AES_KEY_SIZE];
        }
        if (current_size % (size_t)AES_KEY_SIZE == 0) {
            key_schedule_core(temp_word, rcon_iteration++);
        }

        if (AES_KEY_SIZE == AES_KEY_SIZES[AES_256] &&
            (current_size % (size_t)AES_KEY_SIZE) == AES_BLOCK_SIZE) {
            for (size_t i = 0; i < WORD_SIZE; i++) {
                temp_word[i] = sbox[temp_word[i]];
            }
        }
        for (size_t i = 0; i < WORD_SIZE; i++) {
            key[current_size%AES_KEY_SIZE] =
                key[current_size%AES_KEY_SIZE] ^ temp_word[i];
            current_size++;
        }

    }

}


static void sub_bytes(aes_state_t * state) {
    for (int r = 0; r < AES_STATE_DIM; ++r) {
        for (int c = 0; c < AES_STATE_DIM; ++c) {
            (*state)[r][c] = sbox[(*state)[r][c]];
        }
    }
}

static void shift_rows(aes_state_t * state) {
    uint8_t temp;
    // Row 1: 1-byte left shift
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // Row 2: 2-byte left shift
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Row 3: 3-byte left shift
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = temp;
}

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

static void mix_columns(aes_state_t * state) {
    uint8_t t[AES_STATE_DIM];
    for (int c = 0; c < AES_STATE_DIM; ++c) {
        for (int r = 0; r < AES_STATE_DIM; ++r) {
            t[r] = (*state)[r][c];
        }

        (*state)[0][c] =
            galois_mul(t[0], 2) ^ galois_mul(t[1], 3) ^ t[2] ^ t[3];
        (*state)[1][c] =
            t[0] ^ galois_mul(t[1], 2) ^ galois_mul(t[2], 3) ^ t[3];
        (*state)[2][c] =
            t[0] ^ t[1] ^ galois_mul(t[2], 2) ^ galois_mul(t[3], 3);
        (*state)[3][c] =
            galois_mul(t[0], 3) ^ t[1] ^ t[2] ^ galois_mul(t[3], 2);
    }
}

static void add_round_key(aes_state_t * state, const uint8_t * round_key, const uint16_t round) {
    for (int c = 0; c < AES_STATE_DIM; ++c) {
        for (int r = 0; r < AES_STATE_DIM; ++r) {
            (*state)[r][c] ^= round_key[(round * AES_BLOCK_SIZE + (c * AES_STATE_DIM + r)) % AES_KEY_SIZE];
        }
    }
}

static void cipher_encrypt_block(aes_state_t *state, uint8_t * key) {
    uint16_t round = 0;
    add_round_key(state, key, round);
    round++;
    uint8_t *round_key;
    for (; round < AES_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        get_round_key(key, round);
        add_round_key(state, key, round);
    }
    sub_bytes(state);
    shift_rows(state);
    get_round_key(key, round);
    add_round_key(state, key, round);
}

void aes_encrypt(const uint8_t * plaintext, uint8_t * ciphertext,
                 const uint8_t * key) {

    aes_state_t state;
    for (int r = 0; r < AES_STATE_DIM; ++r) {
        for (int c = 0; c < AES_STATE_DIM; ++c) {
            state[r][c] = plaintext[r + AES_STATE_DIM * c];
        }
    }

    uint8_t changing_key[AES_KEY_SIZE];
    for (int b = 0; b < AES_KEY_SIZE; ++b) {
        changing_key[b] = key[b];
    }

    cipher_encrypt_block(&state, changing_key);

    for (int r = 0; r < AES_STATE_DIM; ++r) {
        for (int c = 0; c < AES_STATE_DIM; ++c) {
            ciphertext[r + AES_STATE_DIM * c] = state[r][c];
        }
    }
}
