#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "lookuptable.h"

#define SIZE_OF_ARRAY 256
#define ARRAY galois3Old
#define FUNCTION_NAME galois3

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

int main() {
    char filename[256];
    FILE *output = fopen("lookupTableFunctions.cpp", "a");
    fprintf(output, "#include <stdint.h>\n\nuint8_t "TOSTRING(FUNCTION_NAME)"(uint8_t input) {\n    uint8_t bits[8] = {0};\n uint8_t return_value = 0;\n");
    for (uint8_t j = 0; j < 8; j++) {
            fprintf(output, "switch (input) {\n");
    for (uint16_t i = 0; i < SIZE_OF_ARRAY; i++) {
        if ((ARRAY[i] & ((uint8_t)0b1 << j)) != 0) {
            fprintf(output, "case %d:\n",i); 
        }
    }
    fprintf(output, "bits[%d] = 1;\nbreak;\n", j); 

    for (uint16_t i = 0; i < SIZE_OF_ARRAY; i++) {
        if ((ARRAY[i] & ((uint8_t)0b1 << j)) == 0) {
            fprintf(output, "case %d:\n",i); 
        }
    }
    fprintf(output, "bits[%d] = 0;\nbreak;\n", j); 
    fprintf(output, "}\n");
}
    fprintf(output, "return_value = (bits[0] << 0) | (bits[1] << 1) | (bits[2] << 2) | (bits[3] << 3) | (bits[4] << 4) | (bits[5] << 5) | (bits[6] << 6) | (bits[7] << 7);\n");
    fprintf(output, "return return_value;\n}\n");
    fclose(output);
}