#include "galois.h"
#include "util.h"
#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[]) {
    bignum n, k, r, r2, zero, sr, rsr;
    uint32_t a[] = {0x0022522a, 0x000fcb22};
    uint32_t b[] = {0x0022522a, 0x040fcb22};
    uint32_t c[] = {0x4faaf452, 0x123};
    uint32_t z[] = {0x0};
    init_bignum(&n, a, 2);
    init_bignum(&k, b, 2);
    init_bignum(&zero, z, 1);
    init_bignum(&sr, c, 2);
    print_bignum(&n);
    print_bignum(&k);

    add(&r, &n, &k);
    print_bignum(&r);

    bignum_and(&r2, &n, &k);
    print_bignum(&r2);

    printf("%d\n", bignum_is_not_zero(&n));
    printf("%d\n", bignum_is_not_zero(&zero));

    bignum_shift_right_by_one(&rsr, &sr);
    print_bignum(&rsr);

    return 1;
}

