#include "galois.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


void add(bignum *result, bignum *a, bignum *b) {
    int resulting_size = a->size;

    if (a->size < b->size) resulting_size = b->size;

    result->size = resulting_size;
    result->digits = calloc(resulting_size, sizeof(uint32_t));

    for (int i = 0; i < resulting_size; i++) {
        if (i >= a->size) {
            result->digits[i] = b->digits[i];
        }
        else if (i >= b->size) {
            result->digits[i] = a->digits[i];
        }
        else {
            result->digits[i] = a->digits[i] ^ b->digits[i];
        }
    }
}


void sub(bignum *result, bignum *a, bignum *b) {
    add(result, a, b);
}
