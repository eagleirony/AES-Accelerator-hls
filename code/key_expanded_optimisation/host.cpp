#include "cmdlineparser.h"
#include <iostream>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <iomanip>
#include<stdio.h>
#include <stdlib.h>
#include<iostream>
#include <math.h>
#include "ap_fixed.h"
#include <string.h>
#include "aes.h"

// XRT includes
#include "xrt/xrt_bo.h"
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"

#define AES_INPUT_SIZE 16

#define AES_128 0
#define AES_192 1
#define AES_256 2

// Key size for each key size
#define AES_KEY_SIZES (size_t[]){16, 24, 32}
#define AES_KEY_SIZE AES_KEY_SIZES[AES_VERSION]

#define NUM_TEST_SIZES (int[]) {NUM_TESTS_128, NUM_TESTS_192, NUM_TESTS_256}
#define NUM_TESTS_128 1
#define NUM_TESTS_192 1
#define NUM_TESTS_256 1

int aes_version_id = AES_256;
size_t aes_key_size = AES_KEY_SIZES[aes_version_id];
int num_tests = NUM_TEST_SIZES[aes_version_id];

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

int main(int argc, char** argv) {
    // Command Line Parser
    sda::utils::CmdLineParser parser;

    // Switches
    //**************//"<Full Arg>",  "<Short Arg>", "<Description>", "<Default>"
    parser.addSwitch("--xclbin_file", "-x", "input binary file string", "");
    parser.addSwitch("--device_id", "-d", "device index", "0");
    parser.addSwitch("--aes_version", "-v", "AES version", "AES_256");
    parser.parse(argc, argv);

    // Read settings
    std::string binaryFile = parser.value("xclbin_file");
    int device_index = stoi(parser.value("device_id"));
    std::string aes_version = parser.value("aes_version");

    // obtain the aes version and set relevant parameters
    if (aes_version == "AES_256") {
        aes_version_id = AES_256;
        input_files = input_files_256;
        key_files = key_files_256;
        output_files = output_files_256;
    } else if (aes_version == "AES_192") {
        aes_version_id = AES_192;
        input_files = input_files_192;
        key_files = key_files_192;
        output_files = output_files_192;
    } else if (aes_version == "AES_128") {
        aes_version_id = AES_128;
        input_files = input_files_128;
        key_files = key_files_128;
        output_files = output_files_128;
    } else {
        std::cout << "ERROR: Invalid AES Version {valid versions are \"AES_128\", \"AES_192\" or \"AES_256\"}\n";
    }
    aes_key_size = AES_KEY_SIZES[aes_version_id];
    num_tests = NUM_TEST_SIZES[aes_version_id];

    if (argc < 3) {
        parser.printHelp();
        return EXIT_FAILURE;
    }

    std::cout << "Open the device" << device_index << std::endl;
    auto device = xrt::device(device_index);
    std::cout << "Load the xclbin " << binaryFile << std::endl;
    auto uuid = device.load_xclbin(binaryFile);

    auto krnl = xrt::kernel(device, uuid, "aes_encrypt");

    std::cout << "Allocate Buffer in Global Memory\n";
    auto buf_in = xrt::bo(device, sizeof(uint8_t) * AES_INPUT_SIZE, krnl.group_id(0));
    auto buf_out = xrt::bo(device, sizeof(uint8_t) * AES_INPUT_SIZE, krnl.group_id(1));
    auto buf_key = xrt::bo(device, sizeof(uint8_t) * aes_key_size, krnl.group_id(2));


    // Map the contents of the buffer object into host memory
    auto buf_in_map = buf_in.map<uint8_t*>();
    auto buf_out_map = buf_out.map<uint8_t*>();
    auto buf_key_map = buf_key.map<uint8_t*>();

    // kernel access timing objects
    uint64_t total_running_time = 0;
    uint64_t total_kernel_accesses = 0;

    // now run all tests for the given AES version
    for (int j = 0; j < num_tests; j++) {
        std::cout << "Test (" << j << "): ";

        // open the test files
        FILE *input_fd = fopen(input_files[j],"rb+");
        FILE *key_fd = fopen(key_files[j], "rb+");
        FILE *output_fd = fopen(output_files[j], "rb+");
        if (input_fd == NULL || key_fd == NULL || output_fd == NULL) {
            std::cout << "  ERROR: file(s) not opened successfully\n";
            return EXIT_FAILURE;
        }

        size_t r = 0;
        uint8_t golden_output[AES_BLOCK_SIZE];
        uint64_t test_running_time = 0;
        uint64_t test_kernel_accesses = 0;

        // read the key from the key binary file
        r = fread(buf_key_map, sizeof(uint8_t), aes_key_size, key_fd);
        if (r != aes_key_size) {
            std::cout << "  ERROR: Issue reading the key\n";
            return EXIT_FAILURE;
        }
        // synchronise the key_buffer
        buf_key.sync(XCL_BO_SYNC_BO_TO_DEVICE);

        // continually read in data from the input binary file
        while (true) {
            // read from input file, append 0s at the end
            r = fread(buf_in_map, sizeof(uint8_t), AES_BLOCK_SIZE, input_fd);
            if (r == 0) {
                break;
            }
            if (r < AES_BLOCK_SIZE) {
                // PKCS#7 Padding : padded bytes == the number of bytes padded on
                uint8_t padding = AES_BLOCK_SIZE - r;
                for (int i = r; i < AES_BLOCK_SIZE; i++) {
                    buf_in_map[i] = padding;
                }
            }

            // synchronise the input buffer
            buf_in.sync(XCL_BO_SYNC_BO_TO_DEVICE);

            // execute the kernel
            auto start = std::chrono::steady_clock::now();
            
            auto run = krnl(buf_in, buf_out, buf_key);
            run.wait();

            auto end = std::chrono::steady_clock::now();

            auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
            
            test_running_time += elapsed_ns.count();
            test_kernel_accesses++;

            // sync the output buffer and compare to golden output
            buf_out.sync(XCL_BO_SYNC_BO_FROM_DEVICE);

            int r_out = fread(golden_output, sizeof(uint8_t), AES_BLOCK_SIZE, output_fd);
            if (r_out != AES_BLOCK_SIZE) {
                std::cout << "ERROR: Bad golden output file\n";
                return EXIT_FAILURE;
            }

            for (int i = 0; i < AES_BLOCK_SIZE; i++) {
                if (buf_out_map[i] != golden_output[i]) {
                    std::cout << "FAIL: Output in test " << j
                        << " DOES NOT match the golden output" << std::endl;
                    std::cout << "  buf_out_map: ";
                    for (int y = 0; y < AES_BLOCK_SIZE; y++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                            << (uint32_t)buf_out_map[y];
                    }
                    std::cout << std::endl << "golden_output: ";
                    for (int y = 0; y < AES_BLOCK_SIZE; y++) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                            << (uint32_t)golden_output[y];
                    }
                    std::cout << std::endl;
                        return EXIT_FAILURE;
                }
            }

        }

        double average_time = (test_running_time * 1.0) / (test_kernel_accesses * 1.0);
        std::cout << "SUCCESS: Output matches" << std::endl;
        std::cout << "  Test Run Time (ms): " << test_running_time / 1000000 << std::endl;
        std::cout << "  Kernel Accesses: " << test_kernel_accesses << std::endl;
        std::cout << "  Average Kernel Run Time (ns): " << average_time  << std::endl
            << std::endl;

        // at the end of the test, close the fds and print run time and kernel accesses

        total_running_time += test_running_time;
        total_kernel_accesses += test_kernel_accesses;

        fclose(input_fd);
        fclose(key_fd);
        fclose(output_fd);
    }

    double average_time = (total_running_time * 1.0) / (total_kernel_accesses * 1.0);

    // at this point, all of the tests have passed
    std::cout << "*******************************************" << std::endl;
    std::cout << "SUCCESS: Outputs in all tests match the golden outputs" << std::endl;
    std::cout << "Success in AES Version" << aes_version << std::endl;
    std::cout << "----------------------------" << std::endl;
    std::cout << "  Total Run Time (ms): " << total_running_time / 1000000 << std::endl;
    std::cout << "  Kernel Accesses: " << total_kernel_accesses << std::endl;
    std::cout << "  Average Kernel Run Time (ns): " << average_time << std::endl;
    std::cout << "----------------------------" << std::endl;
    std::cout << "*******************************************" << std::endl;

    return 0;
}
