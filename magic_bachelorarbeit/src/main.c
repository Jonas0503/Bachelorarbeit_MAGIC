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
    uint32_t khex[] = {0xb46d1c48, 0x23a92279, 0xcfe73adc, 0x52f3d78d};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum k = init_bignum(khex, 4);

    bignum product = mult(a, b, p, 128);
    printf("Product: ");
    print_bignum(product);

    xor_bignum(&a, true, a, a);
    print_bignum(a);

    return 1;
}

