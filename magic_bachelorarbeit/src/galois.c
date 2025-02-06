#include "galois.h"
#include "bignum.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


const int DEGREE = 128;
extern bignum POLYNOM;  // x**128 + x**7 + x**2 + x + 1


void add(bignum *result, bignum *a, bignum *b) {
    bignum_xor(result, a, b);
}


void sub(bignum *result, bignum *a, bignum *b) {
    bignum_xor(result, a, b);
}


void mult(bignum *result, bignum *a, bignum *b) {
    
}

