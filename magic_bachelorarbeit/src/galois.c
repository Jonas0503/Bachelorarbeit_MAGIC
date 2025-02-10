#include "galois.h"
#include "bignum.h"
#include "util.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


bignum init_irreducible_polynom_128() {
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


void mult(bignum *result, bool already_allocated, bignum a, bignum b, bignum polynom, int polynom_degree) {
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    if (already_allocated) {
        set_existing_bignum_to_zero(result);
    }
    else {
        *result = init_bignum_to_zero();
    }

    while (is_bignum_not_zero(tmp_a) && is_bignum_not_zero(tmp_b)) {
        if (is_bignum_odd(tmp_a)) {
            xor_bignum(result, true, *result, tmp_b);
        }

        shift_right_by_one_bignum(&tmp_a, true, tmp_a);
        shift_left_by_one_bignum(&tmp_b, true, tmp_b);

        if (!is_bignum_inside_galois_field(tmp_b, polynom_degree)) {
            xor_bignum(&tmp_b, true, tmp_b, polynom);
        }
    }

    destroy_bignum(tmp_a);
    destroy_bignum(tmp_b);
}


void mult_inverse(bignum *result, bool already_allocated, bignum n, bignum polynom, int polynom_degree) {
    bignum base = copy_bignum(n);

    // (2**128)-2 -> fermat's little theorem to get the inverse
    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe};
    bignum exponent = init_bignum(hex, 4);

    if (already_allocated) {
        set_existing_bignum_to_one(result);
    }
    else {
        *result = init_bignum_to_one();
    }

    while (is_bignum_not_zero(exponent)) {
        if (is_bignum_odd(exponent)) {
            mult(result, true, *result, base, polynom, polynom_degree);
        }
        mult(&base, true, base, base, polynom, polynom_degree);
        shift_right_by_one_bignum(&exponent, true, exponent);
    }

    destroy_bignum(base);
    destroy_bignum(exponent);
}
