#include "galois.h"
#include "util.h"
#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[]) {
    bignum p = init_irreducible_polynom_128();

    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    uint32_t khex[] = {0x00000000, 0x00000000, 0x5c73070a, 0x328a58e7};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum k = init_bignum(khex, 4);
    print_bignum(k);
    bignum result;

    add(&result, false, a, b);
    print_bignum(result);

    /* mult(&a, true, a, a, p, 128);
    printf("Product: ");
    print_bignum(a);

    mult_inverse(&result, false, k, p, 128);
    printf("Inverse: ");
    print_bignum(result);

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(k);
    destroy_bignum(result); */

    return 1;
}
