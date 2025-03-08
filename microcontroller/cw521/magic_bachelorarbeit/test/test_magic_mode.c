#include "acutest.h"
#include "magic_mode.h"
#include "util_functions.h"

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


void test_verify_one_bit_error_in_ciphertext(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    bignum correct_ciphertext_block = copy_bignum(ciphertext_blocks[0]);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);

    TEST_CHECK(ciphertext_blocks[0].chunks[2] != correct_ciphertext_block.chunks[2]);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(res.ciphertext_blocks[0].chunks[2] == correct_ciphertext_block.chunks[2]);
}


void test_verify_two_bit_error_in_ciphertext(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    bignum correct_ciphertext_block = copy_bignum(ciphertext_blocks[0]);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 100);

    TEST_CHECK(ciphertext_blocks[0].chunks[2] != correct_ciphertext_block.chunks[2]);
    TEST_CHECK(ciphertext_blocks[0].chunks[0] != correct_ciphertext_block.chunks[0]);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(res.ciphertext_blocks[0].chunks[2] == correct_ciphertext_block.chunks[2]);
    TEST_CHECK(res.ciphertext_blocks[0].chunks[0] == correct_ciphertext_block.chunks[0]);
}


void test_verify_one_bit_error_in_tag(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    bignum correct_tag = copy_bignum(tag);
    tag = one_bit_modification(tag, 42);

    TEST_CHECK(tag.chunks[2] != correct_tag.chunks[2]);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(res.tag.chunks[2] == correct_tag.chunks[2]);
}


void test_verify_error_in_two_blocks(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    bignum correct_ciphertext_block_0 = copy_bignum(ciphertext_blocks[0]);
    bignum correct_ciphertext_block_1 = copy_bignum(ciphertext_blocks[1]);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);
    ciphertext_blocks[1] = one_bit_modification(ciphertext_blocks[1], 100);

    TEST_CHECK(ciphertext_blocks[0].chunks[2] != correct_ciphertext_block_0.chunks[2]);
    TEST_CHECK(ciphertext_blocks[1].chunks[0] != correct_ciphertext_block_1.chunks[0]);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(!res.correction_successful);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag));
}


void test_verify_no_error(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 2;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag));
}


void test_verify_two_bit_error_and_threshold_is_one(void) {
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 1;

    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    uint32_t blinding_key[8] = {
        0x50000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t blinding_nonce[2] = {0x1};
    bignum authorized_data = init_bignum_to_zero();

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    bignum correct_ciphertext_block = copy_bignum(ciphertext_blocks[0]);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 100);

    TEST_CHECK(ciphertext_blocks[0].chunks[2] != correct_ciphertext_block.chunks[2]);
    TEST_CHECK(ciphertext_blocks[0].chunks[0] != correct_ciphertext_block.chunks[0]);

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);

    TEST_CHECK(!res.correction_successful);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag));
}


TEST_LIST = {
    {"plaintext_to_blocks_and_back_to_plaintext", test_plaintext_to_blocks_and_back_to_plaintext},
    {"tag_encryption_decryption", test_tag_encryption_decryption},
    {"verify_one_bit_error_in_ciphertext", test_verify_one_bit_error_in_ciphertext},
    {"verify_two_bit_error_in_ciphertext", test_verify_two_bit_error_in_ciphertext},
    {"verify_one_bit_error_in_tag", test_verify_one_bit_error_in_tag},
    {"verify_error_in_two_blocks", test_verify_error_in_two_blocks},
    {"verify_no_error", test_verify_no_error},
    {"verify_two_bit_error_and_threshold_is_one", test_verify_two_bit_error_and_threshold_is_one},
    {NULL, NULL}
};
