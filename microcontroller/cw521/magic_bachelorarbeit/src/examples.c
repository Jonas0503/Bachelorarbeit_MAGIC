#include "examples.h"
#include "galois.h"
#include "util_functions.h"
#include "bignum.h"
#include "salsa20.h"
#include "magic_mode.h"
#include "hamming_code.h"


void magic_mode_complete(char *text, int threshold) {
    uint32_t key[8];
    uint32_t nonce[2];
    random_bignum_key_nonce(key, nonce, 0);

    uint32_t blinding_key[8];
    uint32_t blinding_nonce[2];
    bignum authorized_data = init_bignum_to_zero();
    random_bignum_key_nonce(blinding_key, blinding_nonce, 1);

    const int nob = calculate_number_of_bignums_from_string(text);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, text, key, nonce);

    bignum hash_key = find_hash_key_value(threshold, nob, 3, 0);
    if (!is_bignum_not_zero(hash_key)) {
        return;
    }

    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    for (int i = 0; i < threshold; i++) {
        ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], i);
    }
    volatile verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);
}


void hamming_code_per_block_complete(char *text) {
    int number_of_bignums = calculate_number_of_bignums_from_string(text);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(text);

    uint32_t key[8];
    uint32_t nonce[2];
    random_bignum_key_nonce(key, nonce, 0);

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, text, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    volatile hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);
}
