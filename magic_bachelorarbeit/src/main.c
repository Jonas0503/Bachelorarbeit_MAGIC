#include "galois.h"
#include "util.h"
#include "bignum.h"
#include "salsa20.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[]) {
    uint32_t state[] = {0xd39f0d73, 0x4c3752b7, 0x0375de25, 0xbfbbea88,
        0x31edb330, 0x016ab2db, 0xafc7a630, 0x5610b3cf,
        0x1ff0203f, 0x0f535da1, 0x74933071, 0xee37cc24,
        0x4fc9eb4f, 0x03519c2f, 0xcb1af4f3, 0x58766836};

    uint32_t state_in[16];
    uint32_t state_out[16];

    // rowround(state);
    // columnround(state);

    // doubleround(state);

    // print_internal_state(state);

    // printf("%x\n", littleendian(0x564b1e09));

    // salsa20_hash(state, state_out);

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    uint32_t nonce[2] = {0x0};

    // salsa20_expansion(state_in, state_out, key, nonce);

    uint32_t plaintext[128] = {0x0};
    uint32_t ciphertext[128];

    salsa20_encryption(key, nonce, 0, plaintext, ciphertext, 128);
    for (int i = 0; i < 128; i++) {
        if (i % 4 == 0) printf("\n");
        if (i % 16 == 0) printf("i:%i \n", i/16);
        printf("%08x", ciphertext[i]);
    }
    printf("\n");

    // print_internal_state(state_out);

    return 1;
}
