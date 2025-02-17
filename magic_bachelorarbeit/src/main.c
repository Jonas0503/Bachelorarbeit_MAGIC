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
    bignum res;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    res = string_to_bignum("Hallo Welt! Ich heisse Jonas Gilbert.");
    print_bignum(res);

    bignum *n = plaintext_to_ciphertext_blocks("Hallo Welt! Ich heisse Jonas Gilbert.", key, nonce);

    for (int i = 0; n[i].number_of_chunks == 4; i++) {
        print_bignum(n[i]);
    }

    unsigned char *s = bignum_blocks_to_string(n);

    printf("%s\n", s);

    destroy_bignum(res);

    return 1;
}
