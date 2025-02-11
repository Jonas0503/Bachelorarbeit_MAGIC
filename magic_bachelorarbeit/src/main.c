#include "galois.h"
#include "util.h"
#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[]) {
    bignum p = init_irreducible_polynom_128();

    uint32_t ahex[] = {0x4d8ab6de, 0x23244984, 0xb729b6a2, 0x5aa7aeb7};
    uint32_t bhex[] = {0xda368e24, 0x11d4913c, 0xe7f39d6e, 0xa979eb85};
    uint32_t khex[] = {0x00000000, 0x00000000, 0x5c73070a, 0x328a58e7};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum k = init_bignum(khex, 4);
    print_bignum(k);
    bignum result;

    mult(&a, true, a, a, p, 128);
    printf("Product: ");
    print_bignum(a);

    mult_inverse(&result, false, k, p, 128);
    printf("Inverse: ");
    print_bignum(result);

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(k);
    destroy_bignum(result);

    return 1;
}
