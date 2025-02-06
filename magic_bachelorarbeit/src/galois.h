#ifndef GALOIS_H
#define GALOIS_H

#include "stdint.h"
#include "bignum.h"


void add(bignum *result, bignum *a, bignum *b);
void sub(bignum *result, bignum *a, bignum *b);
void mult(bignum *result, bignum *a, bignum *b);

#endif
