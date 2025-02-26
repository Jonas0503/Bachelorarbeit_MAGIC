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
    // example
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8];
    uint32_t nonce[2];
    random_bignum_key_nonce(key, nonce);

    uint32_t blinding_key[8];
    uint32_t blinding_nonce[2];
    bignum authorized_data = init_bignum_to_zero();
    random_bignum_key_nonce(blinding_key, blinding_nonce);

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    bignum hash_key = find_hash_key_value(threshold, nob, 3);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    print_bignum_array(ciphertext_blocks, nob);
    printf("\n");
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 100);
    print_bignum_array(ciphertext_blocks, nob);
    printf("\n");

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);
    print_bignum_array(res.ciphertext_blocks, nob);

    return 1;
}
