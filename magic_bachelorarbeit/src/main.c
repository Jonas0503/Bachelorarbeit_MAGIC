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

    uint32_t blinding_key[8] = {
        0xa0000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x80000000, 0x0};

    res = string_to_bignum("Hallo Welt! Ich heisse Jonas Gilbert.");
    print_bignum(res);

    bignum *n = plaintext_to_ciphertext_blocks("Hallo Welt! Ich heisse Jonas Gilbert.", key, nonce);

    for (int i = 0; n[i].number_of_chunks == 4; i++) {
        print_bignum(n[i]);
    }

    bignum hash_key = find_hash_key_value(1, 0);
    uint32_t hex_data[] = {0x12ab34cd, 0x0, 0x0, 0x0};
    bignum data = init_bignum(hex_data, 4);
    bignum tag = ciphertext_blocks_to_tag(n, hash_key, data, blinding_key, blinding_nonce);
    printf("tag: ");
    printf("%i ", tag.number_of_chunks);
    print_bignum(tag);

    unsigned char *pt = ciphertext_blocks_to_plaintext_as_str(n, key, nonce);
    printf("Plaintext: %s\n", pt);

    free(pt);
    destroy_bignum(res);
    // destroy_bignum(abc);
    int i = 0;
    for (; n[i].number_of_chunks == 4; i++) {
        destroy_bignum(n[i]);
    }
    destroy_bignum(n[i]);
    free(n);

    return 1;
}
