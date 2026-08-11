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

#include <cstring>
#include <stdint.h>
#include <stdlib.h>

#include "lookupTableFunctions.h"
#include <ap_int.h>

// Internal constants for the AES implementation.
#define BITS_PER_BYTE 8
#define WORD_SIZE 4

// This function keeps the key buffer up to date by modifying the section for
// the upcoming round It also moves the pointer round_key to the start of the
// 128 byte section needed
static void get_round_key(ap_uint<8> key[AES_ROUNDS+1][AES_BLOCK_SIZE], ap_uint<8> round) {
    #pragma HLS inline off
#pragma HLS function_instantiate variable = round
key_expansion:
    for (ap_uint<8> current_size = round << 4, counter = 0;
         counter < AES_BLOCK_SIZE;
         current_size += WORD_SIZE, counter+= WORD_SIZE) {
//#pragma HLS unroll
        ap_uint<8> temp_word[WORD_SIZE];
        if (current_size < AES_KEY_SIZE) {
            continue;
        }
        for (ap_uint<8> i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll
            temp_word[i] = key[(current_size - WORD_SIZE + i) >> 4][(current_size - WORD_SIZE + i) & 0b1111];
        }
    key_size_sbox:
        if (current_size % AES_KEY_SIZE == 0) {
            ap_uint<4> rcon_iteration = current_size / AES_KEY_SIZE;
            ap_uint<8> temp = sbox(temp_word[0]);
            temp_word[0] = sbox(temp_word[1]) ^ rcon(rcon_iteration);
            temp_word[1] = sbox(temp_word[2]);
            temp_word[2] = sbox(temp_word[3]);
            temp_word[3] = temp;
        }
#if AES_VERSION == AES_256
    key_block_s_box:
        if ((current_size % AES_KEY_SIZE) == AES_BLOCK_SIZE) {
            for (ap_uint<8> i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll
                temp_word[i] = sbox(temp_word[i]);
            }
        }
#endif
    key_update:
        for (ap_uint<8> i = 0; i < WORD_SIZE; i++) {
#pragma HLS unroll
            key[round][(current_size + i) & 0b1111] =
                key[(current_size + i - AES_KEY_SIZE) >> 4][(current_size + i - AES_KEY_SIZE) & 0b1111] ^ temp_word[i];
        }
    }
}

static void shift_rows_and_sub_bytes(aes_state_t * state) {
        #pragma HLS inline off
    // Row 0: 0-byte left shift
    (*state)[0][0] = sbox((*state)[0][0]);
    (*state)[0][1] = sbox((*state)[0][1]);
    (*state)[0][2] = sbox((*state)[0][2]);
    (*state)[0][3] = sbox((*state)[0][3]);

    ap_uint<8> temp;
    // Row 1: 1-byte left shift
    temp = sbox((*state)[1][0]);
    (*state)[1][0] = sbox((*state)[1][1]);
    (*state)[1][1] = sbox((*state)[1][2]);
    (*state)[1][2] = sbox((*state)[1][3]);
    (*state)[1][3] = temp;

    // Row 2: 2-byte left shift
    ap_uint<8> temp2 = sbox((*state)[2][0]);
    (*state)[2][0] = sbox((*state)[2][2]);
    (*state)[2][2] = temp2;
    ap_uint<8> temp3 = sbox((*state)[2][1]);
    (*state)[2][1] = sbox((*state)[2][3]);
    (*state)[2][3] = temp3;

    // Row 3: 3-byte left shift
    ap_uint<8> temp4 = sbox((*state)[3][0]);
    (*state)[3][0] = sbox((*state)[3][3]);
    (*state)[3][3] = sbox((*state)[3][2]);
    (*state)[3][2] = sbox((*state)[3][1]);
    (*state)[3][1] = temp4;
}

static void mix_columns(aes_state_t * state) {
        #pragma HLS inline off
    ap_uint<8> t[AES_STATE_DIM];
mix_cols:
    for (ap_uint<8> c = 0; c < AES_STATE_DIM; ++c) {
#pragma HLS unroll
        for (ap_uint<8> r = 0; r < AES_STATE_DIM; ++r) {
#pragma HLS unroll
            t[r] = (*state)[r][c];
        }

        (*state)[0][c] = galois2(t[0]) ^ galois3(t[1]) ^ t[2] ^ t[3];
        (*state)[1][c] = t[0] ^ galois2(t[1]) ^ galois3(t[2]) ^ t[3];
        (*state)[2][c] = t[0] ^ t[1] ^ galois2(t[2]) ^ galois3(t[3]);
        (*state)[3][c] = galois3(t[0]) ^ t[1] ^ t[2] ^ galois2(t[3]);
    }
}

static void add_round_key(aes_state_t * state, const ap_uint<8> round_key[AES_BLOCK_SIZE]) {
    add_rk:
    for (ap_uint<8> c = 0; c < AES_STATE_DIM; ++c) {
#pragma HLS unroll
        for (ap_uint<8> r = 0; r < AES_STATE_DIM; ++r) {
#pragma HLS unroll
            (*state)[r][c] ^= round_key[(c * AES_STATE_DIM + r)];
        }
    }
}

static void cipher_encrypt_block(aes_state_t * state, ap_uint<8> key[AES_ROUNDS+1][AES_BLOCK_SIZE]) {
        #pragma HLS inline off
#pragma HLS pipeline II = 1
    add_round_key(state, key[0]);
encrypt_block:
    for (ap_uint<8> round = 1; round < AES_ROUNDS; round++) {
#pragma HLS unroll
        shift_rows_and_sub_bytes(state);
        mix_columns(state);
        add_round_key(state, key[round]);
    }
    shift_rows_and_sub_bytes(state);
    add_round_key(state, key[AES_ROUNDS]);
}

void aes_encrypt(const uint8_t* plaintext, const uint32_t size, uint8_t* ciphertext, const uint8_t* key) {


    // instantiate arrays for input/output
    //  perhaps create an array of in_out_states to create memory elements for
    //  unrolling the encrypt loop?
    ap_uint<32> loops = size >> 4;
    ap_uint<32> extraBlocks = (size & 0b1111);
    ap_uint<8> diff = AES_BLOCK_SIZE - extraBlocks;
    if (extraBlocks == 0) {
        loops +=1;
    }
    ap_uint<8> roundKeys[AES_ROUNDS+1][AES_BLOCK_SIZE];
    ap_uint<8> keyin[AES_KEY_SIZE];
    #pragma HLS array_partition variable = roundKeys type = complete
    #pragma HLS array_partition variable = keyin type = complete
    memcpy(keyin, key, AES_KEY_SIZE);
    for (ap_uint<8> i = 0; i < AES_KEY_SIZE; i++) {
        #pragma HLS unroll
        roundKeys[i >> 4][i % AES_BLOCK_SIZE] = keyin[i];
    }
    for (ap_uint<8> genKeys = 1; genKeys <= AES_ROUNDS; genKeys++) {
        #pragma HLS pipeline off
        get_round_key(roundKeys, genKeys);
    }

aes_encrypt_loop:
    for (ap_uint<32> i = 0; i < size; i += AES_BLOCK_SIZE) {
#pragma HLS unroll factor = 4
#pragma HLS pipeline off
        aes_state_t state;
#pragma HLS array_partition variable = state type = complete
    ap_uint<8> plaintext_copied[AES_BLOCK_SIZE];
    #pragma HLS array_partition variable = plaintext_copied type = complete
    memcpy(plaintext_copied, &(plaintext[i]), AES_BLOCK_SIZE);
    // populate input array with PKCS#7 padding
    populate_input_arr:
        for (ap_uint<8> c = 0; c < AES_STATE_DIM; c++) {
#pragma HLS unroll
            for (ap_uint<8> r = 0; r < AES_STATE_DIM; r++) {
#pragma HLS unroll
                state[r][c] = ((i == (loops << 4)) &&
                               ((c * AES_STATE_DIM + r) >= extraBlocks))
                                  ? diff
                                  : plaintext_copied[c * AES_STATE_DIM + r];
            }
        }
    ap_uint<8> keyin[AES_KEY_SIZE];
    #pragma HLS array_partition variable = keyin type = complete
    memcpy(keyin, key, AES_KEY_SIZE);
        // call aes_encrypt_block
        cipher_encrypt_block(&state, roundKeys);

    // store output array in ciphertext
    ap_uint<8> ciphertext_precopy[AES_BLOCK_SIZE];
    #pragma HLS array_partition variable = ciphertext_precopy type = complete
    populate_output_arr:
        for (ap_uint<8> c = 0; c < AES_STATE_DIM; c++) {
#pragma HLS unroll
            for (ap_uint<8> r = 0; r < AES_STATE_DIM; r++)
#pragma HLS unroll
                ciphertext_precopy[c * AES_STATE_DIM + r] = state[r][c];
        }
        memcpy(&ciphertext[i], ciphertext_precopy, AES_BLOCK_SIZE);
    }
}
