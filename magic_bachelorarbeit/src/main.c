#include "galois.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[])
{
    bignum n;
    new_bignum(&n, "42");
    print_bignum_big_endian(&n);

    bignum a, b, r;
    new_bignum(&a, "42");
    print_bignum_big_endian(&a);
    new_bignum(&b, "3");
    print_bignum_big_endian(&b);

    add(&r, &a, &b);
    print_bignum_big_endian(&r);

    destroy_bignum(&n);
    destroy_bignum(&a);
    destroy_bignum(&b);
    destroy_bignum(&r);

    return 0;
}

