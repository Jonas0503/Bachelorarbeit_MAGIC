#include "galois.h"
#include "util.h"
#include "bignum.h"
#include "salsa20.h"
#include "magic_mode.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"


int main(int argc, char const *argv[]) {
    int bit_indices[3] = {127, 126, 42};
    polynom_to_bignum(bit_indices, 3);

    return 1;
}
