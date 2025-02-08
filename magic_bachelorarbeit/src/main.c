#include "galois.h"
#include "util.h"
#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[]) {
    bignum p = init_polynom();

    uint32_t ahex[] = {0x4d8ab6de, 0x23244984, 0xb729b6a2, 0x5aa7aeb7};
    uint32_t bhex[] = {0xda368e24, 0x11d4913c, 0xe7f39d6e, 0xa979eb85};

    bignum a = bignum_init(ahex, 4);
    bignum b = bignum_init(bhex, 4);

    bignum product = mult(a, b);
    printf("Product: ");
    bignum_print(product);

    bignum_print(b);
    b = bignum_shift_left_by_one(b);
    bignum_print(b);

    b = bignum_xor(b, p);
    bignum_print(p);
    bignum_print(b);

    return 1;
}

