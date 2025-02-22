#include "galois.h"
#include "bignum.h"
#include "util.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


// The irreducible polynomial
// x**128 + x**7 + x**2 + x + 1
// uint32_t chunks[5] = {0x1, 0x00000000, 0x00000000, 0x00000000, 0x00000087};
// the number 0x1 in chunks[0] is not important for the following calculations
// only important at XOR in mult() when the MSB is a one after a left shift -> the first chunk would be zero
const bignum IRREDUCIBLE_POLYNOMIAL_128 = {.chunks = {0x00000000, 0x00000000, 0x00000000, 0x00000087}};


bignum add(bignum a, bignum b) {
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    return xor_bignum(tmp_a, tmp_b);
}


bignum mult(bignum a, bignum b) {
    // copies the bignums because wrong results could occur when the parameters a, b and the return variable are the same
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    bignum result = init_bignum_to_zero();
    bool inside_galois_field;

    // "visit" all bits or until one number is zero
    while (is_bignum_not_zero(tmp_a) && is_bignum_not_zero(tmp_b)) {
        // when a is odd add b
        if (is_bignum_odd(tmp_a)) {
            result = xor_bignum(result, tmp_b);
        }

        // divide a by 2
        tmp_a = shift_right_by_one_bignum(tmp_a);

        // check if after the "multiplication" b is outside of he Galois Field and then multiply b by 2
        inside_galois_field = is_bignum_inside_galois_field_after_left_shift(tmp_b);
        tmp_b = shift_left_by_one_bignum(tmp_b);

        // when b is a "polynomial" outside the galois field add (XOR) the irreducible polynomial with b (the same as b mod irreducible_polynomial)
        if (!inside_galois_field) {
            tmp_b = xor_bignum(tmp_b, IRREDUCIBLE_POLYNOMIAL_128);
        }
    }

    return result;
}


bignum mult_inverse(bignum n) {
    // copies the bignum because wrong results could occur when the parameter n and the return variable are the same
    bignum base = copy_bignum(n);

    // n**((2**128)-2) = n**(-1) -> fermat's little theorem to get the inverse
    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe};
    bignum exponent = init_bignum(hex);

    bignum result = init_bignum_to_one();

    // example: base^45 = base^32 * base^8 * base^4 * base^1
    while (is_bignum_not_zero(exponent)) {
        // when the last bit is a one, multiply by the squared base
        if (is_bignum_odd(exponent)) {
            result = mult(result, base);
        }
        // square the base -> (base^1, base^2, base^4, base^8, ...)
        base = mult(base, base);

        // get the next bit
        exponent = shift_right_by_one_bignum(exponent);
    }

    return result;
}
