# Version 2
## Version 2.1
03/08/2026
+ Modified the aes.h file to make aes version control easier
+ Created lookuptable.c file containing the sbox and rcon for code readability, added lookup table version of the required galois field calls to remove the need for multiplication and added array partition and bind storage pragmas so the lookup tables can be accessed in parrallel with logic implemented as LUTs
+ Merged sub bytes and shift rows into a single function call to ensure that shift rows is implemented as wires as a precaution with seperate temp variables to minimise risk of bad dependency analysis
+ Modified mix_columns to use the lookup tables for the galois field multiplication and added unroll to the loops
+ Added loop unrolling to the add_round_key and function instantiation on the round variable to allow for better synthesis optimisation
+ Added pipeline pragma to cipher_encrypt_block and unrolled the loop which with the function instantiation should allow for round based optimisation and better pipelining
+ Modified the round key generation process from a preprocessing step which generates and stores the entire key before any encyrption into a round by round process with less required storage for pipelining and smaller latency as the round key can be generated on the side
    + Added Function instantiation based on rounds to allow each get round key function to be optimised based on the specific round value
    + Unrolled the get_round_key loops
    + Converted all key accesses to use the circular array
    + Inlined the key_schedule_core and word_rotate_left so wires for word_rotate_left are more likely and allow for easier synthesis
    + Added preprocessor conditional for the AES_VERSION based logic to remove entirely if not necessary so no unused hardware logic


# Version 1
## Version 1.1
30/07/2026
+ Created kernel files in code/kernel, this currently includes unoptimised code and key_gen improved code
+ Created testcase binaries inlcuding input, key and golden output files (inside simple_test directory and inside testbin in relevant kernel or hardware sections)
+ Created C test-bench, most recent version currently in code/kernel/unoptimised directory
+ Updated host.cpp file (although it still needs to be tested)
+ Confirmed the functionality of the kernel files through the C test-bench

## Version 1.0
24/07/2026
+ Created host.cpp file
+ TODO: Add input and golden output files, create aes-128 kernel

# Version 0
## Version 0.0
03/07/2026
+ Created Project_Updates.md
+ Added [Project_Plan.pdf](./Project_Plan.pdf)
+ Updated [README.md](./README.md) to include group members and a link to project updates
