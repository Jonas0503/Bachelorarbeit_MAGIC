// inspired by this blog: https://austinhenley.com/blog/bignum2.html
#include "bignum.h"

#include "stdint.h"
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#include "stdio.h"


void new_bignum(bignum *n, char *string) {
    int length = strlen(string);
    int number_of_chunks = (length + 8) / 9;

    n->size = number_of_chunks;
    n->digits = calloc(length, sizeof(uint32_t));

    for (int i = 0; i < length; i++) {
        int chunck_position = i / 9;
        int position_in_chunk = i % 9;
        uint32_t digit = string[length - 1 - i] - '0';
        uint32_t multiplier = 1;

        for (int k = 0; k < position_in_chunk; k++) {
            multiplier *= 10;
        }

        n->digits[chunck_position] += digit * multiplier;
    }
}


void destroy_bignum(bignum *n) {
    free(n->digits);
}


void print_bignum_little_endian(bignum *n) {
    bool first_block = true;

    for (int i = 0; i < n->size; i++) {
        if (first_block) {
            printf("%u", n->digits[i]);
            first_block = false;
        }
        else {
            printf("%09u", n->digits[i]);
        }
    }

    if (first_block) printf("0");

    printf("\n");
}


void print_bignum_big_endian(bignum *n) {
    // TODO: Remove leading zeros
    bool first_block = true;

    for (int i = n->size; i >= 0; i--) {
        if (first_block) {
            printf("%u", n->digits[i]);
            first_block = false;
        }
        else {
            printf("%09u", n->digits[i]);
        }
    }

    if (first_block) printf("0");

    printf("\n");
}
