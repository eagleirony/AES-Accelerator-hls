#include <ap_int.h>

#ifndef LOOKUP_H
#define LOOKUP_H
ap_uint<8> rcon(ap_uint<4> input);
ap_uint<8> galois2(ap_uint<8> input);
ap_uint<8> galois3(ap_uint<8> input);
ap_uint<8> sbox(ap_uint<8> input);
#endif