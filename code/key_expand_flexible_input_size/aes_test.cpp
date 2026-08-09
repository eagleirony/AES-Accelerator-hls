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

#define NUM_TEST_SIZES (int[]) {NUM_TESTS_128, NUM_TESTS_192, NUM_TESTS_256}
#define NUM_TESTS NUM_TEST_SIZES[AES_VERSION]
#define NUM_TESTS_128 1
#define NUM_TESTS_192 1
#define NUM_TESTS_256 2

const char *input_files_128[NUM_TESTS_128] = {"testbin/128_plaintext.bin"};
const char *key_files_128[NUM_TESTS_128] = {"testbin/128_key.bin"};
const char *output_files_128[NUM_TESTS_128] = {"testbin/128_ciphertext.bin"};

const char *input_files_192[NUM_TESTS_192] = {"testbin/192_plaintext.bin"};
const char *key_files_192[NUM_TESTS_192] = {"testbin/192_key.bin"};
const char *output_files_192[NUM_TESTS_192] = {"testbin/192_ciphertext.bin"};

const char *input_files_256[NUM_TESTS_256] = {"testbin/256_plaintext.bin", "testbin/256_plaintext_1.bin"};
const char *key_files_256[NUM_TESTS_256] = {"testbin/256_key.bin", "testbin/256_key.bin"};
const char *output_files_256[NUM_TESTS_256] = {"testbin/256_ciphertext.bin", "testbin/256_ciphertext_1.bin"};

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
		printf("\tERROR: AES Version not supported\n");
		return 1;
	}

	int tests_failed[NUM_TESTS] = {0};

	// now test each of the testbenches for that aes version
	for (int test = 0; test < NUM_TESTS; test++) {
		printf("**********\n");
		printf("|Test: %02d |\n", test);
		printf("**********\n\n");

		printf("Opening Files\n");

		
		FILE *input_fd = fopen(input_files[test],"rb+");
		FILE *output_fd = fopen(output_files[test], "rb+");
		FILE *key_fd = fopen(key_files[test], "rb+");
		if (input_fd == NULL || key_fd == NULL || output_fd == NULL) {
			printf("\tERROR: File not opened successfully\n");
			continue;
		}
		printf("Files Opened Successfully\n");
		
		uint8_t key[AES_KEY_SIZE+1];
		uint8_t expected_output[AES_BLOCK_SIZE+1];
		size_t r_in, r_out = 1;

		printf("Running AES on input file %s\n", input_files[test]);

		// step 1: read the key
		r_in = fread(key, sizeof(uint8_t), AES_KEY_SIZE, key_fd);

		// step 2: now we read the entirity of the input file, first we get the input file size in bytes
		fseek(input_fd, 0, SEEK_END);
		long input_size = ftell(input_fd);
		if (input_size < 0) {
			printf("\tERROR: Issue with getting file size\n");
			tests_failed[test] = 1;
			continue;
		}
		printf("File size: %d Bytes\n", input_size);
		fseek(input_fd, 0, SEEK_SET);

		uint8_t *input_buf = (uint8_t*)malloc(sizeof(uint8_t) * (input_size + 1));
		if (input_buf == NULL) {
			printf("\tERROR: File too large, %dBytes\n", input_size);
			tests_failed[test] = 1;
			continue;
		}
		r_in = fread(input_buf, sizeof(uint8_t), input_size, input_fd);
		if (r_in != input_size) {
			printf("\tERROR: Issue with reading file\n");

			continue;
		}
		input_buf[input_size] = '\0'; // shouldn't affect operation of aes since we pass in size

		// for the output buffer, we will need to extend input_size to max of an AES_BLOCK
		int padding = input_size % AES_BLOCK_SIZE;
		uint8_t *output_buf = (uint8_t*)malloc(sizeof(uint8_t) * (input_size + padding + 1));


		// now run AES encrypt on this input
		aes_encrypt(input_buf, input_size, output_buf, key);

		// now compare output to golden output
		for (int i = 0; i < input_size; i += AES_BLOCK_SIZE) {
			r_out = fread(expected_output, sizeof(uint8_t), AES_BLOCK_SIZE, output_fd);
			if (r_out != AES_BLOCK_SIZE) {
				printf("\tERROR: Bad golden output file\n");
				tests_failed[test] = 1;
				continue;
			}

			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				if (expected_output[j] != output_buf[i+j]) {
					printf("FAIL: Output DOES NOT match the golden output\n");
					printf("\t\tError occurred in the %d'th block of output\nTODO: Print out each block in hex.\n", i / AES_BLOCK_SIZE);
					tests_failed[test] = 1;
				}
			}
		}

		if (tests_failed[test]) continue;

		printf("Test #%d finished successfully\n", test);

		fclose(input_fd);
		fclose(key_fd);
		fclose(output_fd);
	}

	for (int i = 0; i < NUM_TESTS; i++) {
		if (tests_failed[i]) {
			printf("*******************************************\n");
			printf("FAIL : (\n");
			printf("*******************************************\n");
			return 1;
		}
	}

	printf("*******************************************\n");
	printf("SUCCESS: Output matches golden output\n");
	printf("*******************************************\n");

	return 0;
}
