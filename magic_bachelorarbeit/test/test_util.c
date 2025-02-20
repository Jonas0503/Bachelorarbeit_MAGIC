#include "acutest.h"
#include "util.h"

#include "string.h"


void test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits(void) {
    uint64_t a = 0xff53cda4;
    uint32_t b, c, expected_b, expected_c;
    expected_b = 0x0;
    expected_c = 0xff53cda4;

    convert_64_bit_into_two_32_bit(a, &b, &c);

    TEST_CHECK(expected_b == b);
    TEST_CHECK(expected_c == c);
}


void test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits(void) {
    uint64_t a = 0xff53cda44357;
    uint32_t b, c, expected_b, expected_c;
    expected_b = 0xff53;
    expected_c = 0xcda44357;

    convert_64_bit_into_two_32_bit(a, &b, &c);

    TEST_CHECK(expected_b == b);
    TEST_CHECK(expected_c == c);
}


void test_convert_two_32_bit_into_64_bit(void) {
    uint32_t b, c;
    b = 0xff53;
    c = 0xcda44357;

    uint64_t res_expected = 0xff53cda44357;
    uint64_t res = convert_two_32_bit_into_64_bit(b, c);

    TEST_CHECK(res_expected == res);
}


void test_string_to_bignum(void) {
    char *text = "Hallo Welt! 123 - ABC?";
    uint32_t expected[] = {0x4861, 0x6C6C6F20, 0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};

    bignum result = string_to_bignum(text);

    TEST_CHECK(result.number_of_chunks == 6);
    for (int i = 0; i < result.number_of_chunks; i++) {
        TEST_CHECK(result.chunks[i] == expected[i]);
    }

    destroy_bignum(result);
}


void test_string_to_bignum_with_empty_string(void) {
    char *text = "";
    bignum result = string_to_bignum(text);

    TEST_CHECK(result.number_of_chunks == 1);
    TEST_CHECK(result.chunks[0] == 0x0);

    destroy_bignum(result);
}


void test_bignum_to_string(void) {
    uint32_t hex[] = {0x4861, 0x6C6C6F20, 0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    bignum n = init_bignum(hex, 6);
    char *expected = "Hallo Welt! 123 - ABC?";

    char *result = (char *)bignum_to_string(n);

    TEST_CHECK(strcmp(result, expected) == 0);

    destroy_bignum(n);
}


void test_calculate_number_of_ciphertext_blocks(void) {
    uint32_t a_hex[] = {0x213ad298, 0x656fdb21, 0x656fdb21, 0x656fdb21};
    uint32_t b_hex[] = {0x3453acca, 0x3453acca, 0x8797efa0, 0x3453acca};
    bignum a = init_bignum(a_hex, 4);
    bignum b = init_bignum(b_hex, 4);
    bignum c = init_bignum_to_zero();
    bignum blocks[] = {a, b, c};

    int result = calculate_number_of_ciphertext_blocks(blocks);

    TEST_CHECK(result == 2);

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(c);
}


void test_ciphertext_bignum_blocks_to_one_bignum(void) {
    uint32_t a_hex[] = {0x213ad298, 0x656fdb21, 0x656fdb21, 0x656fdb21};
    uint32_t b_hex[] = {0x3453acca, 0x3453acca, 0x8797efa0, 0x3453acca};
    bignum a = init_bignum(a_hex, 4);
    bignum b = init_bignum(b_hex, 4);
    bignum c = init_bignum_to_zero();
    bignum blocks[] = {a, b, c};

    uint32_t expected[] = {
        0x213ad298, 0x656fdb21, 0x656fdb21, 0x656fdb21,
        0x3453acca, 0x3453acca, 0x8797efa0, 0x3453acca
    };

    bignum result = ciphertext_bignum_blocks_to_one_bignum(blocks);

    TEST_CHECK(result.number_of_chunks == 8);
    for (int i = 0; i < result.number_of_chunks; i++) {
        TEST_CHECK(result.chunks[i] == expected[i]);
    }

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(c);
    destroy_bignum(result);
}


void test_pad_no_full_128_bit_block(void) {
    uint32_t a_hex[] = {0x6fdb21, 0x656fdb21, 0x656fdb21};
    bignum a = init_bignum(a_hex, 3);
    uint32_t expected[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x1};

    bignum result;
    pad(&result, false, a);

    TEST_CHECK(result.number_of_chunks == 4);
    for (int i = 0; i < result.number_of_chunks; i++) {
        TEST_CHECK(result.chunks[i] == expected[i]);
    }

    destroy_bignum(a);
    destroy_bignum(result);
}


void test_pad_full_128_bit_block_overwriting_input(void) {
    uint32_t a_hex[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x12345678};
    bignum a = init_bignum(a_hex, 4);
    uint32_t expected[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x12345678, 0x4, 0x4, 0x4, 0x4};

    pad(&a, true, a);

    TEST_CHECK(a.number_of_chunks == 8);
    for (int i = 0; i < a.number_of_chunks; i++) {
        TEST_CHECK(a.chunks[i] == expected[i]);
    }

    destroy_bignum(a);
}


void test_unpad_no_full_128_bit_block(void) {
    uint32_t a_hex[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x1};
    bignum a = init_bignum(a_hex, 4);
    uint32_t expected[] = {0x6fdb21, 0x656fdb21, 0x656fdb21};

    bignum result;
    unpad(&result, false, a);

    TEST_CHECK(result.number_of_chunks == 3);
    for (int i = 0; i < result.number_of_chunks; i++) {
        TEST_CHECK(result.chunks[i] == expected[i]);
    }

    destroy_bignum(a);
    destroy_bignum(result);
}


void test_unpad_full_128_bit_block_overwriting_input(void) {
    uint32_t a_hex[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x12345678, 0x4, 0x4, 0x4, 0x4};
    bignum a = init_bignum(a_hex, 8);
    uint32_t expected[] = {0x6fdb21, 0x656fdb21, 0x656fdb21, 0x12345678};

    unpad(&a, true, a);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < a.number_of_chunks; i++) {
        TEST_CHECK(a.chunks[i] == expected[i]);
    }

    destroy_bignum(a);
}


void test_hamming_weight(void) {
    uint32_t a_hex[] = {0x123de};
    bignum a = init_bignum(a_hex, 1);

    int result = hamming_weight(a);

    TEST_CHECK(result == 10);

    destroy_bignum(a);
}


TEST_LIST = {
    {"convert_64_bit_into_two_32_bit_a_is_less_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits},
    {"convert_64_bit_into_two_32_bit_a_is_more_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits},
    {"convert_two_32_bit_into_64_bit", test_convert_two_32_bit_into_64_bit},
    {"string_to_bignum", test_string_to_bignum},
    {"string_to_bignum_with_empty_string", test_string_to_bignum_with_empty_string},
    {"bignum_to_string", test_bignum_to_string},
    {"calculate_number_of_ciphertext_blocks", test_calculate_number_of_ciphertext_blocks},
    {"ciphertext_bignum_blocks_to_one_bignum", test_ciphertext_bignum_blocks_to_one_bignum},
    {"pad_no_full_128_bit_block", test_pad_no_full_128_bit_block},
    {"pad_full_128_bit_block_overwriting_input", test_pad_full_128_bit_block_overwriting_input},
    {"unpad_no_full_128_bit_block", test_unpad_no_full_128_bit_block},
    {"unpad_full_128_bit_block_overwriting_input", test_unpad_full_128_bit_block_overwriting_input},
    {"hamming_weight", test_hamming_weight},
    {NULL, NULL}
};
