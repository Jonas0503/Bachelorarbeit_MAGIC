#ifndef BIGNUM_H
#define BIGNUM_H

#include "stdint.h"
#include "stdbool.h"


typedef struct {
    uint32_t *chunks;
    int number_of_chunks;
} bignum;

bignum init_bignum(uint32_t *hex, int size);
bignum init_bignum_to_zero();
void set_existing_bignum_to_zero(bignum *n);
bignum init_bignum_to_one();
void set_existing_bignum_to_one(bignum *n);
void destroy_bignum(bignum n);
void print_bignum(bignum n);
void xor_bignum(bignum *result, bool already_malloc, bignum a, bignum b);
bool is_bignum_not_zero(bignum n);
void shift_left_by_one_bignum(bignum *result, bool already_allocated, bignum n);
void shift_right_by_one_bignum(bignum *result, bool already_allocated, bignum n);
void shift_right_by_x_bignum(bignum *result, bool already_allocated, bignum n, int x);
bool is_bignum_odd(bignum n);
bool is_bignum_inside_galois_field(bignum n, int degree);
bignum copy_bignum(bignum n);

#endif
