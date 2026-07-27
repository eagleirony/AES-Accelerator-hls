/**
 * @file aes.h
 * @brief Public API for a clean and simple AES implementation.
 *
 * @details This header defines the public interface for AES (Advanced
 * Encryption Standard) encryption and decryption. It supports key sizes of
 * 128, 192, and 256 bits and operates on 16-byte (128-bit) blocks. The
 * implementation is designed for clarity and correctness.
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * Public Compile-Time Constants
 * ========================================================================= */

/** @brief The block size for AES, which is always 128 bits (16 bytes). */
#define AES_BLOCK_SIZE 16

/** @brief The dimension of the square AES state matrix (4x4). */
#define AES_STATE_DIM 4

#define AES_128 0
#define AES_192 1
#define AES_256 2

#define AES_VERSION AES_256

// Number of rounds for each key size.
#define AES_ROUNDS_SIZES (size_t[]){10, 12, 14}
#define AES_ROUNDS AES_ROUNDS_SIZES[AES_VERSION]

// Key size for each key size
#define AES_KEY_SIZES (size_t[]){16, 24, 32}
#define AES_KEY_SIZE AES_KEY_SIZES[AES_VERSION]


/* ============================================================================
 * Public Enums and Typedefs
 * ========================================================================= */

/** @brief A type definition for the 4x4 byte AES state matrix. */
typedef uint8_t aes_state_t[AES_STATE_DIM][AES_STATE_DIM];

/* ============================================================================
 * Public API
 * ========================================================================= */

void aes_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, const uint8_t* key);


#endif // AES_H