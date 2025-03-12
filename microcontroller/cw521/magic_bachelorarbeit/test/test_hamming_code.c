#include "acutest.h"
#include "hamming_code.h"
#include "util_functions.h"
#include "salsa20.h"

#include "stdio.h"


void test_calculate_number_of_ciphertext_blocks_with_parity_from_string_full_block(void) {
    char *text = "Hallo WeltABC123";
    int expected = 2;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_from_string(text);

    TEST_CHECK(expected == result);
}


void test_calculate_number_of_ciphertext_blocks_with_parity_from_string_two_blocks(void) {
    char *text = "Hallo WeltABC123J";
    int expected = 3;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_from_string(text);

    TEST_CHECK(expected == result);
}


void test_bignums_to_bit_arrays_with_space_for_parity_bits(void) {
    uint32_t hex[4] = {0xa0ba8f54, 0x1c67d2e5, 0xb3f27aa0, 0xbeeeae3c};
    bignum ciphertext_blocks[1] = {init_bignum(hex)};

    int number_of_blocks = 1;
    int number_of_blocks_with_parity = 2;

    bool expected[2][128] = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0
        },
        {
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
        }
    };

    bool result[number_of_blocks_with_parity][128];
    bignums_to_bit_arrays_with_space_for_parity_bits(result, ciphertext_blocks, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            TEST_CHECK(expected[i][k] == result[i][k]);
        }
    }
}


void test_set_parity_bits(void) {
    int number_of_blocks_with_parity = 2;

    bool expected[2][128] = {
        {
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0
        },
        {
            0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
            1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
        }
    };

    bool result[2][128] = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0
        },
        {
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
        }
    };
    set_parity_bits(result, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            TEST_CHECK(expected[i][k] == result[i][k]);
        }
    }
}


void test_bit_arrays_to_bignum_array(void) {
    bool bit_arrays[2][128] = {
        {
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0
        },
        {
            0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
            1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
        }
    };

    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum expected[2];
    init_bignum_array(expected, 2, hex, 8);

    bignum result[2];
    bit_arrays_to_bignum_array(result, 2, bit_arrays);

    for (int i = 0; i < 2; i++) {
        TEST_CHECK(are_bignums_equal(expected[i], result[i]));
    }
}


void test_add_parity_to_bignum_array(void) {
    int number_of_blocks = 1;
    int number_of_blocks_with_parity = 2;

    uint32_t hex_ciphertext[4] = {0xa0ba8f54, 0x1c67d2e5, 0xb3f27aa0, 0xbeeeae3c};
    bignum ciphertext_blocks[1] = {init_bignum(hex_ciphertext)};

    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum expected[2];
    init_bignum_array(expected, 2, hex, 8);

    bignum result[number_of_blocks_with_parity];
    add_parity_to_bignum_array(result, ciphertext_blocks, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < 2; i++) {
        TEST_CHECK(are_bignums_equal(expected[i], result[i]));
    }
}


void test_bignum_array_to_bit_arrays(void) {
    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum array[2];
    init_bignum_array(array, 2, hex, 8);

    bool expected[2][128] = {
        {
            1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0
        },
        {
            0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
            1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0
        }
    };

    bool result[2][128];
    bignum_array_to_bit_arrays(result, array, 2);

    for (int i = 0; i < 2; i++) {
        for (int k = 0; k < 128; k++) {
            TEST_CHECK(expected[i][k] == result[i][k]);
        }
    }
}


void test_verify_hamming_code_two_bit_error_in_one_block(void) {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[0] = one_bit_modification(blocks_parity[0], 100);

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);

    TEST_CHECK(!res.correction_successful);
    TEST_CHECK(!res.one_bit_error);
    TEST_CHECK(res.two_bit_error);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks_with_parity[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag_with_parity));
}


void test_verify_hamming_code_one_bit_error_in_one_block(void) {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(res.one_bit_error);
    TEST_CHECK(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        TEST_CHECK(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity_correct[i]));
    }
    TEST_CHECK(!is_bignum_not_zero(res.tag_with_parity));
}


void test_verify_hamming_code_no_error(void) {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(!res.one_bit_error);
    TEST_CHECK(!res.two_bit_error);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks_with_parity[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag_with_parity));
}


void test_verify_hamming_code_two_bit_error_in_two_blocks(void) {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[0] = one_bit_modification(blocks_parity[0], 100);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 33);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 45);

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);

    TEST_CHECK(!res.correction_successful);
    TEST_CHECK(!res.one_bit_error);
    TEST_CHECK(res.two_bit_error);
    TEST_CHECK(!is_bignum_not_zero(res.ciphertext_blocks_with_parity[0]));
    TEST_CHECK(!is_bignum_not_zero(res.tag_with_parity));
}


void test_verify_hamming_code_one_bit_error_in_two_blocks(void) {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 110);

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);

    TEST_CHECK(res.correction_successful);
    TEST_CHECK(res.one_bit_error);
    TEST_CHECK(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        TEST_CHECK(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity_correct[i]));
    }
    TEST_CHECK(!is_bignum_not_zero(res.tag_with_parity));
}


void test_remove_parity_from_encrypted_ciphertext_blocks(void) {
    uint32_t hex_expected[4] = {0xa0ba8f54, 0x1c67d2e5, 0xb3f27aa0, 0xbeeeae3c};
    bignum expected[1] = {init_bignum(hex_expected)};

    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum array[2];
    init_bignum_array(array, 2, hex, 8);

    bignum result[1];
    remove_parity_from_encrypted_ciphertext_blocks(result, array, 2, 1);

    TEST_CHECK(are_bignums_equal(result[0], expected[0]));
}


TEST_LIST = {
    {"calculate_number_of_ciphertext_blocks_with_parity_from_string_full_block", test_calculate_number_of_ciphertext_blocks_with_parity_from_string_full_block},
    {"calculate_number_of_ciphertext_blocks_with_parity_from_string_two_blocks", test_calculate_number_of_ciphertext_blocks_with_parity_from_string_two_blocks},
    {"bignums_to_bit_arrays_with_space_for_parity_bits", test_bignums_to_bit_arrays_with_space_for_parity_bits},
    {"set_parity_bits", test_set_parity_bits},
    {"bit_arrays_to_bignum_array", test_bit_arrays_to_bignum_array},
    {"add_parity_to_bignum_array", test_add_parity_to_bignum_array},
    {"bignum_array_to_bit_arrays", test_bignum_array_to_bit_arrays},
    {"verify_hamming_code_two_bit_error_in_one_block", test_verify_hamming_code_two_bit_error_in_one_block},
    {"verify_hamming_code_one_bit_error_in_one_block", test_verify_hamming_code_one_bit_error_in_one_block},
    {"verify_hamming_code_no_error", test_verify_hamming_code_no_error},
    {"verify_hamming_code_two_bit_error_in_two_blocks", test_verify_hamming_code_two_bit_error_in_two_blocks},
    {"verify_hamming_code_one_bit_error_in_two_blocks", test_verify_hamming_code_one_bit_error_in_two_blocks},
    {"remove_parity_from_encrypted_ciphertext_blocks", test_remove_parity_from_encrypted_ciphertext_blocks},
    {NULL, NULL}
};
