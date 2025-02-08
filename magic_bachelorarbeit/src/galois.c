#include "galois.h"
#include "bignum.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


const int DEGREE = 128;


bignum init_polynom() {
    // x**128 + x**7 + x**2 + x + 1
    uint32_t hex_poly[] = {0x1, 0x00000000, 0x00000000, 0x00000000, 0x00000087};

    return bignum_init(hex_poly, 5);
}


bignum add(bignum a, bignum b) {
    return bignum_xor(a, b);
}


bignum sub(bignum a, bignum b) {
    return bignum_xor(a, b);
}


bignum mult(bignum a, bignum b) {
    bignum polynom = init_polynom();
    bignum result = bignum_init_zero();

    while (bignum_is_not_zero(a) && bignum_is_not_zero(b)) {
        if (bignum_is_odd(a)) {
            result = bignum_xor(result, b);
        }

        a = bignum_shift_right_by_one(a);
        b = bignum_shift_left_by_one(b);

        if (!bignum_is_inside_galois_field(b, DEGREE)) {
            b = bignum_xor(b, polynom);
        }
    }

    return result;
}

