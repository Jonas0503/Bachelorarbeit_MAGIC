#include "galois.h"
#include "bignum.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


bignum init_polynom() {
    // x**128 + x**7 + x**2 + x + 1
    uint32_t hex_poly[] = {0x1, 0x00000000, 0x00000000, 0x00000000, 0x00000087};

    return init_bignum(hex_poly, 5);
}


bignum add(bignum a, bignum b) {
    bignum result = init_bignum_to_zero();
    xor_bignum(&result, true, a, b);
    return result;
}


bignum sub(bignum a, bignum b) {
    return add(a, b);
}


bignum mult(bignum a, bignum b, bignum polynom, int polynom_degree) {
    bignum result = init_bignum_to_zero();

    while (is_bignum_zero(a) && is_bignum_zero(b)) {
        if (is_bignum_odd(a)) {
            xor_bignum(&result, true, result, b);
        }

        shift_right_by_one_bignum(&a, true, a);
        shift_left_by_one_bignum(&b, true, b);

        if (!is_bignum_inside_galois_field(b, polynom_degree)) {
            xor_bignum(&b, true, b, polynom);
        }
    }

    return result;
}
