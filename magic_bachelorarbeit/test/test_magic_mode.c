#include "acutest.h"
#include "magic_mode.h"
#include "util.h"

#include "string.h"


void test_plaintext_to_blocks_and_back_to_plaintext(void) {
    char *text = "Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!";
    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    bignum *blocks = plaintext_to_ciphertext_blocks(text, key, nonce);
    char *decrypted_blocks = (char *)ciphertext_blocks_to_plaintext_as_str(blocks, key, nonce);

    TEST_CHECK(strcmp(text, decrypted_blocks) == 0);

    destroy_bignum_array(blocks, calculate_number_of_ciphertext_blocks(blocks));
}


void test_tag_encryption_decryption(void) {
    char *text = "Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!";
    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};
    bignum *blocks = plaintext_to_ciphertext_blocks(text, key, nonce);

    uint32_t blinding_key[8] = {
        0x90000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum hash_key = find_hash_key_value(-1, -1);  // TODO
    bignum authorized_data = init_bignum_to_zero();

    bignum input_blinding_cipher = calculate_input_for_blinding_cipher(blocks, hash_key, authorized_data);
    bignum tag = ciphertext_blocks_to_tag(blocks, hash_key, authorized_data, blinding_key, blinding_nonce);
    bignum tag_decrypted = decrypt_tag(tag, blinding_key, blinding_nonce);

    TEST_CHECK(are_bignums_equal(input_blinding_cipher, tag_decrypted));
}


TEST_LIST = {
    {"plaintext_to_blocks_and_back_to_plaintext", test_plaintext_to_blocks_and_back_to_plaintext},
    {"tag_encryption_decryption", test_tag_encryption_decryption},
    {NULL, NULL}
};
