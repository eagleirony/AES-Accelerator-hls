#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "lookuptable.h"


int main() {
    char filename[256];
    FILE *output = fopen("lookupTableFunctions.c", "a");
    fprintf(output, "uint8_t rcon(uint8_t input) {\nswitch (input) {\n");
    for (uint16_t i = 0; i < 16; i++) {
        uint8_t outputVal = rcon[i];
        fprintf(output, "case %d:\n return %#x;\n",i, outputVal);
    }
    fprintf(output, "}}\n");
    fclose(output);
}