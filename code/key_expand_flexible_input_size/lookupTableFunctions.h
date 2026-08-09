#include <stdint.h>

#ifndef LOOKUP_H
#define LOOKUP_H
uint8_t rcon(uint8_t input);
uint8_t galois2(uint8_t input);
uint8_t galois3(uint8_t input);
uint8_t sbox(uint8_t input);
#endif