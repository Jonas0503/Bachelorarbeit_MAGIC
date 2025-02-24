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

    const int number_of_blocks = calculate_number_of_bignums_from_string(text);
    bignum ciphertext_blocks[number_of_blocks];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, text, key, nonce);

    const int number_of_chars = calculate_number_of_chars_from_bignum_array(ciphertext_blocks, number_of_blocks);
    unsigned char plaintext[number_of_chars];
    ciphertext_blocks_to_plaintext_as_str(plaintext, ciphertext_blocks, number_of_blocks, key, nonce);

    TEST_CHECK(strcmp(text, (char *)plaintext) == 0);
}


void test_tag_encryption_decryption(void) {
    char *text = "Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!";
    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    const int number_of_blocks = calculate_number_of_bignums_from_string(text);
    bignum ciphertext_blocks[number_of_blocks];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, text, key, nonce);

    uint32_t blinding_key[8] = {
        0x90000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    
    // 221385673651417484972498539470727584786
    uint32_t hex_for_hash_key[4] = {0xa68d546e, 0xb6c431b9, 0x78f700db, 0xca6a9c12};
    bignum hash_key = init_bignum(hex_for_hash_key);
    bignum authorized_data = init_bignum_to_zero();

    bignum input_blinding_cipher = calculate_input_for_blinding_cipher(ciphertext_blocks, number_of_blocks, hash_key, authorized_data);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, number_of_blocks, hash_key, authorized_data, blinding_key, blinding_nonce);
    bignum tag_decrypted = decrypt_tag(tag, blinding_key, blinding_nonce);

    TEST_CHECK(are_bignums_equal(input_blinding_cipher, tag_decrypted));
}


TEST_LIST = {
    {"plaintext_to_blocks_and_back_to_plaintext", test_plaintext_to_blocks_and_back_to_plaintext},
    {"tag_encryption_decryption", test_tag_encryption_decryption},
    {NULL, NULL}
};
