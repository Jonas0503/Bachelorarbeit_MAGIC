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


void add(bignum *result, bool already_allocated, bignum a, bignum b) {
    // Copies the bignums because wrong results occur when the parameters result, a, b are all the same input variable (all pointing to same memory?!)
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    xor_bignum(result, already_allocated, tmp_a, tmp_b);

    destroy_bignum(tmp_a);
    destroy_bignum(tmp_b);
}


void sub(bignum *result, bool already_allocated, bignum a, bignum b) {
    add(result, already_allocated, a, b);
}


void mult(bignum *result, bool already_allocated, bignum a, bignum b, bignum polynom, int polynom_degree) {
    // Copies the bignums because wrong results occur when the parameters result, a, b are all the same input variable (all pointing to same memory?!)
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    if (already_allocated) {
        set_existing_bignum_to_zero(result);
    }
    else {
        *result = init_bignum_to_zero();
    }

    // "visit" all bits or until one number is zero
    while (is_bignum_not_zero(tmp_a) && is_bignum_not_zero(tmp_b)) {
        // when a is odd add b
        if (is_bignum_odd(tmp_a)) {
            xor_bignum(result, true, *result, tmp_b);
        }

        // divide a by 2
        shift_right_by_one_bignum(&tmp_a, true, tmp_a);

        // multiply b by 2
        shift_left_by_one_bignum(&tmp_b, true, tmp_b);

        // when b is a "polynomial" outside the galois field add (XOR) the irreducible polynomial with b (the same as b mod irreducible_polynomial)
        if (!is_bignum_inside_galois_field(tmp_b, polynom_degree)) {
            xor_bignum(&tmp_b, true, tmp_b, polynom);
        }
    }

    destroy_bignum(tmp_a);
    destroy_bignum(tmp_b);
}


void mult_inverse(bignum *result, bool already_allocated, bignum n, bignum polynom, int polynom_degree) {
    // Copies the bignums because wrong results occur when the parameters result and n are the same input variable (all pointing to same memory?!)
    bignum base = copy_bignum(n);

    // n**((2**polynom_degree)-2) = n**-1 -> fermat's little theorem to get the inverse
    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe};
    bignum exponent = init_bignum(hex, 4);

    if (already_allocated) {
        set_existing_bignum_to_one(result);
    }
    else {
        *result = init_bignum_to_one();
    }

    // example: base^45 = base^32 * base^8 * base^4 * base^1
    while (is_bignum_not_zero(exponent)) {
        // when the last bit is a one, multiply by the squared base
        if (is_bignum_odd(exponent)) {
            mult(result, true, *result, base, polynom, polynom_degree);
        }
        // square the base -> (base^1, base^2, base^4, base^8, ...)
        mult(&base, true, base, base, polynom, polynom_degree);

        // get the next bit
        shift_right_by_one_bignum(&exponent, true, exponent);
    }

    destroy_bignum(base);
    destroy_bignum(exponent);
}
