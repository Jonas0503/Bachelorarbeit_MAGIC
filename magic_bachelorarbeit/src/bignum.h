#ifndef BIGNUM_H
#define BIGNUM_H

#include "stdint.h"
#include "stdbool.h"


typedef struct {
    uint32_t *chunks;
    int number_of_chunks;
} bignum;

void init_bignum(bignum *bn, uint32_t *hex, int size);
void print_bignum(bignum *bn);
void bignum_xor(bignum *result, bignum *a, bignum *b);
void bignum_and(bignum *result, bignum *a, bignum *b);
bool bignum_is_not_zero(bignum *n);
void bignum_shift_left_by_one(bignum *result, bignum *n);
void bignum_shift_right_by_one(bignum *result, bignum *n);

#endif
