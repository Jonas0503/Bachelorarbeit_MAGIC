#ifndef BIGNUM_H
#define BIGNUM_H

#include "stdint.h"
#include "stdbool.h"


typedef struct {
    uint32_t *chunks;
    int number_of_chunks;
} bignum;

bignum bignum_init(uint32_t *hex, int size);
bignum bignum_init_zero();
bignum bignum_init_one();
void bignum_destroy(bignum n);
void bignum_print(bignum n);
bignum bignum_xor(bignum a, bignum b);
bignum bignum_and(bignum a, bignum b);
bool bignum_is_not_zero(bignum n);
bignum bignum_shift_left_by_one(bignum n);
bignum bignum_shift_right_by_one(bignum n);
bignum bignum_shift_right_by_x(bignum n, int x);
bool bignum_is_odd(bignum n);
bool bignum_is_inside_galois_field(bignum n, int degree);

#endif
