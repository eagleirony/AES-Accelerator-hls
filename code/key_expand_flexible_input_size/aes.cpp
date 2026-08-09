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

#include <stdint.h>
#include <stdlib.h>

#include "lookuptable.h"

// Internal constants for the AES implementation.
#define BITS_PER_BYTE 8
#define WORD_SIZE 4

// This function keeps the key buffer up to date by modifying the section for
// the upcoming round It also moves the pointer round_key to the start of the
// 128 byte section needed
static void get_round_key(uint8_t * key, uint8_t round) {
#pragma HLS function_instantiate variable = round
key_expansion:
    for (uint8_t current_size = round * AES_BLOCK_SIZE;
         current_size < round * AES_BLOCK_SIZE + AES_BLOCK_SIZE;
         current_size += WORD_SIZE) {
#pragma HLS unroll factor = AES_BLOCK_SIZE
        uint8_t temp_word[WORD_SIZE];
        if (current_size < AES_KEY_SIZE) {
            current_size += WORD_SIZE;
            continue;
        }
        for (uint8_t i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll factor = WORD_SIZE
            temp_word[i] = key[(current_size - WORD_SIZE + i) % AES_KEY_SIZE];
        }
    key_size_sbox:
        if (current_size % AES_KEY_SIZE == 0) {
            uint8_t rcon_iteration = current_size / AES_KEY_SIZE;
            uint8_t temp = sbox[temp_word[0]];
            temp_word[0] = sbox[temp_word[1]] ^ rcon[rcon_iteration];
            temp_word[1] = sbox[temp_word[2]];
            temp_word[2] = sbox[temp_word[3]];
            temp_word[3] = temp;
        }
#if AES_VERSION == AES_256
    key_block_sbox:
        if ((current_size % AES_KEY_SIZE) == AES_BLOCK_SIZE) {
            for (uint8_t i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll factor = WORD_SIZE
                temp_word[i] = sbox[temp_word[i]];
            }
        }
#endif
    key_update:
        for (uint8_t i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll factor = WORD_SIZE
            key[(current_size + i) % AES_KEY_SIZE] =
                key[(current_size + i) % AES_KEY_SIZE] ^ temp_word[i];
        }
    }
}

static void shift_rows_and_sub_bytes(aes_state_t * state) {
    // Row 0: 0-byte left shift
    (*state)[0][0] = sbox[(*state)[0][0]];
    (*state)[0][1] = sbox[(*state)[0][1]];
    (*state)[0][2] = sbox[(*state)[0][2]];
    (*state)[0][3] = sbox[(*state)[0][3]];

    uint8_t temp;
    // Row 1: 1-byte left shift
    temp = sbox[(*state)[1][0]];
    (*state)[1][0] = sbox[(*state)[1][1]];
    (*state)[1][1] = sbox[(*state)[1][2]];
    (*state)[1][2] = sbox[(*state)[1][3]];
    (*state)[1][3] = temp;

    // Row 2: 2-byte left shift
    uint8_t temp2 = sbox[(*state)[2][0]];
    (*state)[2][0] = sbox[(*state)[2][2]];
    (*state)[2][2] = temp2;
    uint8_t temp3 = sbox[(*state)[2][1]];
    (*state)[2][1] = sbox[(*state)[2][3]];
    (*state)[2][3] = temp3;

    // Row 3: 3-byte left shift
    uint8_t temp4 = sbox[(*state)[3][0]];
    (*state)[3][0] = sbox[(*state)[3][3]];
    (*state)[3][3] = sbox[(*state)[3][2]];
    (*state)[3][2] = sbox[(*state)[3][1]];
    (*state)[3][1] = temp4;
}

static void mix_columns(aes_state_t * state) {
    uint8_t t[AES_STATE_DIM];
mix_cols:
    for (uint8_t c = 0; c < AES_STATE_DIM; ++c) {
#pragma HLS unroll factor = AES_STATE_DIM
        for (uint8_t r = 0; r < AES_STATE_DIM; ++r) {
#pragma HLS unroll factor = AES_STATE_DIM
            t[r] = (*state)[r][c];
        }

        (*state)[0][c] = galois2[t[0]] ^ galois3[t[1]] ^ t[2] ^ t[3];
        (*state)[1][c] = t[0] ^ galois2[t[1]] ^ galois3[t[2]] ^ t[3];
        (*state)[2][c] = t[0] ^ t[1] ^ galois2[t[2]] ^ galois3[t[3]];
        (*state)[3][c] = galois3[t[0]] ^ t[1] ^ t[2] ^ galois2[t[3]];
    }
}

static void add_round_key(aes_state_t * state, const uint8_t * round_key,
                          const uint8_t round) {
#pragma HLS function_instantiate variable = round
add_rk:
    for (uint8_t c = 0; c < AES_STATE_DIM; ++c) {
#pragma HLS unroll factor = AES_STATE_DIM
        for (uint8_t r = 0; r < AES_STATE_DIM; ++r) {
#pragma HLS unroll factor = AES_STATE_DIM
            (*state)[r][c] ^=
                round_key[(round * AES_BLOCK_SIZE + (c * AES_STATE_DIM + r)) %
                          AES_KEY_SIZE];
        }
    }
}

static void cipher_encrypt_block(aes_state_t * state, uint8_t * key) {
#pragma HLS pipeline II = 1
    add_round_key(state, key, 0);
encrypt_block:
    for (uint8_t round = 1; round < AES_ROUNDS; round++) {
#pragma HLS unroll
        get_round_key(key, round);
        shift_rows_and_sub_bytes(state);
        mix_columns(state);
        add_round_key(state, key, round);
    }
    get_round_key(key, AES_ROUNDS);
    shift_rows_and_sub_bytes(state);
    add_round_key(state, key, AES_ROUNDS);
}

void aes_encrypt(const uint8_t * plaintext, const uint32_t size,
                 uint8_t * ciphertext, const uint8_t * key) {
#pragma HLS array_partition variable = sbox type = complete
#pragma HLS bind_storage variable = sbox type = ROM_NP impl = LUTRAM
#pragma HLS array_partition variable = galois2 type = complete
#pragma HLS bind_storage variable = galois2 type = ROM_NP impl = LUTRAM
#pragma HLS array_partition variable = galois3 type = complete
#pragma HLS bind_storage variable = galois3 type = ROM_NP impl = LUTRAM
#pragma HLS array_partition variable = rcon type = complete
#pragma HLS bind_storage variable = rcon type = ROM_NP impl = LUTRAM


    // instantiate arrays for input/output
    //  perhaps create an array of in_out_states to create memory elements for
    //  unrolling the encrypt loop?
    uint32_t loops = size >> 4;
    uint32_t extraBlocks = (size & 0b1111);
    uint32_t diff = AES_BLOCK_SIZE - extraBlocks;

aes_encrypt_loop:
    for (uint32_t i = 0; i < size; i += AES_BLOCK_SIZE) {
// #pragma HLS unroll factor = AES_BLOCK_SIZE
#pragma HLS pipeline II = 1
        aes_state_t state;
#pragma HLS array_partition variable = state type = complete

    // populate input array with PKCS#7 padding
    populate_input_arr:
        for (uint8_t c = 0; c < AES_STATE_DIM; c++) {
#pragma HLS unroll factor = AES_STATE_DIM
            for (uint8_t r = 0; r < AES_STATE_DIM; r++) {
#pragma HLS unroll factor = AES_STATE_DIM
                state[r][c] = ((i == (loops << 4)) &&
                               ((c * AES_STATE_DIM + r) >= extraBlocks))
                                  ? plaintext[i + c * AES_STATE_DIM + r]
                                  : diff;
            }
        }

        uint8_t changing_key[AES_KEY_SIZE];
#pragma HLS array_partition variable = changing_key type = complete
    copy_key:
        for (uint8_t b = 0; b < AES_KEY_SIZE; ++b) {
#pragma HLS unroll factor = AES_KEY_SIZE
            changing_key[b] = key[b];
        }

        // call aes_encrypt_block
        cipher_encrypt_block(&state, changing_key);

    // store output array in ciphertext
    populate_output_arr:
        for (uint8_t c = 0; c < AES_STATE_DIM; c++) {
#pragma HLS unroll
            for (uint8_t r = 0; r < AES_STATE_DIM; r++)
#pragma HLS unroll
                ciphertext[i + c * AES_STATE_DIM + r] = state[r][c];
        }
    }
}
