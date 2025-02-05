// inspired by this blog: https://austinhenley.com/blog/bignum2.html
#include "stdint.h"


typedef struct {
    uint32_t *digits;
    int size;
} bignum;

void new_bignum(bignum *n, char *string);
void destroy_bignum(bignum *n);
void print_bignum_little_endian(bignum *n);
void print_bignum_big_endian(bignum *n);
