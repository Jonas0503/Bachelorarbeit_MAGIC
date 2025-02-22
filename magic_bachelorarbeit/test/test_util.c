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


void test_calculate_number_of_bignums_from_string(void) {
    char *text = "Hallo Welt! 123 - ABC?";
    const int result = calculate_number_of_bignums_from_string(text);

    TEST_CHECK(result == 2);
}


void test_calculate_number_of_bignums_from_empty_string(void) {
    char *text = "";
    const int result = calculate_number_of_bignums_from_string(text);

    TEST_CHECK(result == 1);
}


void test_string_to_bignum(void) {
    char *text = "Hallo Welt! 123 - ABC?";
    uint32_t expected1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t expected0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};

    bignum result[2];
    string_to_bignum_array(result, text);

    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < 4; i++) {
            if (k == 0) TEST_CHECK(result[k].chunks[i] == expected0[i]);
            if (k == 1) TEST_CHECK(result[k].chunks[i] == expected1[i]);
        }
    }
}


void test_string_to_bignum_with_empty_string(void) {
    char *text = "";
    bignum result[1];
    string_to_bignum_array(result, text);

    TEST_CHECK(!is_bignum_not_zero(result[0]));
}


void test_calculate_number_of_chars_from_bignum_array(void) {
    uint32_t hex1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t hex0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};
    bignum n0 = init_bignum(hex0);
    bignum n1 = init_bignum(hex1);
    bignum array[2] = {n0, n1};

    const int result = calculate_number_of_chars_from_bignum_array(array, 2);

    TEST_CHECK(result == 23);
}


void test_bignum_to_string(void) {
    uint32_t hex1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t hex0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};
    bignum n0 = init_bignum(hex0);
    bignum n1 = init_bignum(hex1);
    bignum array[2] = {n0, n1};

    char *expected = "Hallo Welt! 123 - ABC?";
    unsigned char result[23];

    bignum_array_to_string(result, array, 2);

    TEST_CHECK(strcmp((char *)result, expected) == 0);
}


void test_ciphertext_bignum_blocks_to_one_bignum(void) {
    uint32_t a_hex[] = {0x213ad298, 0x656fdb21, 0x656fdb21, 0x656fdb21};
    uint32_t b_hex[] = {0x3453acca, 0x3453acca, 0x8797efa0, 0x3453acca};
    bignum a = init_bignum(a_hex);
    bignum b = init_bignum(b_hex);
    bignum blocks[2] = {a, b};

    uint32_t expected[8] = {
        0x213ad298, 0x656fdb21, 0x656fdb21, 0x656fdb21,
        0x3453acca, 0x3453acca, 0x8797efa0, 0x3453acca
    };
    uint32_t result[8];

    ciphertext_bignum_blocks_to_one_array(result, blocks, 2);

    for (int i = 0; i < 8; i++) {
        TEST_CHECK(result[i] == expected[i]);
    }
}


void test_hamming_weight(void) {
    uint32_t a_hex[] = {0x0, 0x0, 0x0, 0x123de};
    bignum a = init_bignum(a_hex);

    int result = hamming_weight(a);

    TEST_CHECK(result == 10);
}


TEST_LIST = {
    {"convert_64_bit_into_two_32_bit_a_is_less_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits},
    {"convert_64_bit_into_two_32_bit_a_is_more_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits},
    {"convert_two_32_bit_into_64_bit", test_convert_two_32_bit_into_64_bit},
    {"calculate_number_of_bignums_from_string", test_calculate_number_of_bignums_from_string},
    {"calculate_number_of_bignums_from_empty_string", test_calculate_number_of_bignums_from_empty_string},
    {"string_to_bignum_array", test_string_to_bignum},
    {"string_to_bignum_with_empty_string", test_string_to_bignum_with_empty_string},
    {"calculate_number_of_chars_from_bignum_array", test_calculate_number_of_chars_from_bignum_array},
    {"bignum_array_to_string", test_bignum_to_string},
    {"ciphertext_bignum_blocks_to_one_bignum", test_ciphertext_bignum_blocks_to_one_bignum},
    {"hamming_weight", test_hamming_weight},
    {NULL, NULL}
};
