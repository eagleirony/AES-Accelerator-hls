/*
This is DFT computation using matrix vector multiplication form.
INPUT:
	In_R, In_I[]: Real and Imag parts of Complex signal in time domain.
OUTPUT:
	In_R, In_I[]: Real and Imag parts of Complex signal in frequency domain.

*/

#include<stdio.h>
#include <stdlib.h>
#include<iostream>
#include <math.h>
#include "aes.h"

#define MAX_FILE_NAME_LEN 256

#define NUM_TEST_SIZES (int[]) {NUM_TESTS_128, NUM_TESTS_192, NUM_TESTS_256}
#define NUM_TESTS NUM_TEST_SIZES[AES_VERSION]
#define NUM_TESTS_128 1
#define NUM_TESTS_192 1
#define NUM_TESTS_256 1

const char *input_files_128[NUM_TESTS_128] = {"testbin/128_plaintext.bin"};
const char *key_files_128[NUM_TESTS_128] = {"testbin/128_key.bin"};
const char *output_files_128[NUM_TESTS_128] = {"testbin/128_ciphertext.bin"};

const char *input_files_192[NUM_TESTS_192] = {"testbin/192_plaintext.bin"};
const char *key_files_192[NUM_TESTS_192] = {"testbin/192_key.bin"};
const char *output_files_192[NUM_TESTS_192] = {"testbin/192_ciphertext.bin"};

const char *input_files_256[NUM_TESTS_256] = {"testbin/256_plaintext.bin"};
const char *key_files_256[NUM_TESTS_256] = {"testbin/256_key.bin"};
const char *output_files_256[NUM_TESTS_256] = {"testbin/256_ciphertext.bin"};

const char **input_files;
const char **key_files;
const char **output_files;

int main()
{	
	if (AES_VERSION == AES_128) {
		input_files = input_files_128;
		key_files = key_files_128;
		output_files = output_files_128;
		printf("Testing AES-128 Mode\n");
	} else if (AES_VERSION == AES_192) {
		input_files = input_files_192;
		key_files = key_files_192;
		output_files = output_files_192;
		printf("Testing AES-192 Mode\n");
	} else if (AES_VERSION == AES_256) {
		input_files = input_files_256;
		key_files = key_files_256;
		output_files = output_files_256;
		printf("Testing AES-256 Mode\n");
	} else {
		printf("ERROR: AES Version not supported\n");
		return 1;
	}

	// now test each of the testbenches for that aes version
	for (int j = 0; j < NUM_TESTS; j++) {
		printf("**********\n");
		printf("|Test: %02d |\n", j);
		printf("**********\n\n");

		printf("Opening Files\n");

		
		FILE *input_fd = fopen(input_files[j],"rb+");
		FILE *key_fd = fopen(key_files[j], "rb+");
		FILE *output_fd = fopen(output_files[j], "rb+");
		if (input_fd == NULL || key_fd == NULL || output_fd == NULL) {
			printf("ERROR: File not opened successfully\n");
			return 1;
		}
		printf("Files Opened Successfully\n");
		
		uint8_t key[AES_KEY_SIZE+1];
		uint8_t input_stream[AES_BLOCK_SIZE+1];
		uint8_t output_stream[AES_BLOCK_SIZE+1];
		uint8_t expected_output[AES_BLOCK_SIZE+1];
		size_t r_in, r_out = 1;

		printf("Running AES on input file\n");

		// step 1: read the key
		r_in = fread(key, sizeof(uint8_t), AES_KEY_SIZE, key_fd);

		// step 2: now, we continually read from input and check that the aes encryption matches the read output
		r_in = fread(input_stream, sizeof(uint8_t), AES_BLOCK_SIZE, input_fd);
		if (r_in < AES_BLOCK_SIZE) {
			for (int i = r_in; i < AES_BLOCK_SIZE; i++) {
				input_stream[i] = 0x00;
			}
		}
		
		while (r_in > 0) {
			// 1. run aes_encrypt on the input and plaintext
			aes_encrypt(input_stream, output_stream, key);

			// 2. fetch expected output
			r_out = fread(expected_output, sizeof(uint8_t), AES_BLOCK_SIZE, output_fd);

			// 3. check that expected_output == output_stream
			for (int i = 0; i < r_out; i++) {
				if (output_stream[i] != expected_output[i]) {
					fprintf(stdout, "*******************************************\n");
					fprintf(stdout, "FAIL: Output DOES NOT match the golden output\n");
					fprintf(stdout, "*******************************************\n");
				}
			}

			// 4. read the next section from input
			r_in  = fread(input_stream, sizeof(uint8_t), AES_BLOCK_SIZE, input_fd);
			if (r_in < AES_BLOCK_SIZE) {
				for (int i = r_in; i < AES_BLOCK_SIZE; i++) {
					input_stream[i] = 0x00;
				}
			}
		}

		// make sure the file lengths is as expected
		r_out = fread(expected_output, sizeof(uint8_t), AES_BLOCK_SIZE, output_fd);
		if (r_out != 0) {
			printf("ERROR: Somehow input file and expected output file reads got desynced\n");
			return 1;
		}

		fprintf(stdout, "*******************************************\n");
		fprintf(stdout, "PASS: The output matches the golden output!\n");
		fprintf(stdout, "*******************************************\n");

		return 0;
	}
}
