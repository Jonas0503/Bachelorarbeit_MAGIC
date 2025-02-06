#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdbool.h"


void init_bignum(bignum *bn, uint32_t *hex, int size) {
    bn->number_of_chunks = size;
    bn->chunks = calloc(size, sizeof(uint32_t));

    for (int i = 0; i < size; i++) {
        bn->chunks[i] = hex[size-1-i];
    }
}


void print_bignum(bignum *bn) {
    if (bn->number_of_chunks == 0) printf("0");

    for (int i = bn->number_of_chunks-1; i >= 0; i--) {
        if (i <= bn->number_of_chunks-2) {
            printf("%08x", bn->chunks[i]);
        }
        else {
            printf("%x", bn->chunks[i]);
        }
    }

    printf("\n");
}


void bignum_xor(bignum *result, bignum *a, bignum *b) {
    int resulting_size = a->number_of_chunks;

    if (a->number_of_chunks < b->number_of_chunks) resulting_size = b->number_of_chunks;

    result->number_of_chunks = resulting_size;
    result->chunks = malloc(sizeof(uint32_t) * resulting_size);

    for (int i = 0; i < resulting_size; i++) {
        if (i >= a->number_of_chunks) {
            result->chunks[i] = b->chunks[i];
        }
        else if (i >= b->number_of_chunks) {
            result->chunks[i] = a->chunks[i];
        }
        else {
            result->chunks[i] = a->chunks[i] ^ b->chunks[i];
        }
    }
}


void bignum_and(bignum *result, bignum *a, bignum *b) {
    int resulting_size = a->number_of_chunks;

    if (a->number_of_chunks < b->number_of_chunks) resulting_size = b->number_of_chunks;

    result->number_of_chunks = resulting_size;
    result->chunks = malloc(sizeof(uint32_t) * resulting_size);

    for (int i = 0; i < resulting_size; i++) {
        if (i >= a->number_of_chunks || i >= b->number_of_chunks) {
            result->chunks[i] = 0x00000000;
        }
        else {
            result->chunks[i] = a->chunks[i] & b->chunks[i];
        }
    }
}


bool bignum_is_not_zero(bignum *n) {
    if (n->number_of_chunks == 0) return false;

    for (int i = 0; i < n->number_of_chunks; i++) {
        if (n->chunks[i] != 0x0) return true;
    }

    return false;
}


void bignum_shift_left_by_one(bignum *result, bignum *n) {
    // TODO
}


void bignum_shift_right_by_one(bignum *result, bignum *n) {
    // TODO
}
