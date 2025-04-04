#ifndef LOCAL
#include "magic_bachelorarbeit/src/util_functions.h"
#include "magic_bachelorarbeit/src/galois.h"
#else
#include "util_functions.h"
#include "galois.h"
#endif
#include "string.h"
#include "assert.h"


void test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits() {
    uint64_t a = 0xff53cda4;
    uint32_t b, c, expected_b, expected_c;
    expected_b = 0x0;
    expected_c = 0xff53cda4;

    convert_64_bit_into_two_32_bit(a, &b, &c);

    assert(expected_b == b);
    assert(expected_c == c);
}


void test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits() {
    uint64_t a = 0xff53cda44357;
    uint32_t b, c, expected_b, expected_c;
    expected_b = 0xff53;
    expected_c = 0xcda44357;

    convert_64_bit_into_two_32_bit(a, &b, &c);

    assert(expected_b == b);
    assert(expected_c == c);
}


void test_convert_two_32_bit_into_64_bit() {
    uint32_t b, c;
    b = 0xff53;
    c = 0xcda44357;

    uint64_t res_expected = 0xff53cda44357;
    uint64_t res = convert_two_32_bit_into_64_bit(b, c);

    assert(res_expected == res);
}


void test_calculate_number_of_bignums_from_string() {
    char *text = "Hallo Welt! 123 - ABC?";
    const int result = calculate_number_of_bignums_from_string(text);

    assert(result == 2);
}


void test_calculate_number_of_bignums_from_empty_string() {
    char *text = "";
    const int result = calculate_number_of_bignums_from_string(text);

    assert(result == 1);
}


void test_string_to_bignum() {
    char *text = "Hallo Welt! 123 - ABC?";
    uint32_t expected1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t expected0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};

    bignum result[2];
    string_to_bignum_array(result, text);

    for (int k = 0; k < 2; k++) {
        for (int i = 0; i < 4; i++) {
            if (k == 0) assert(result[k].chunks[i] == expected0[i]);
            if (k == 1) assert(result[k].chunks[i] == expected1[i]);
        }
    }
}


void test_string_to_bignum_with_empty_string() {
    char *text = "";
    bignum result[1];
    string_to_bignum_array(result, text);

    assert(!is_bignum_not_zero(result[0]));
}


void test_calculate_number_of_chars_from_bignum_array() {
    uint32_t hex1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t hex0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};
    bignum n0 = init_bignum(hex0);
    bignum n1 = init_bignum(hex1);
    bignum array[2] = {n0, n1};

    const int result = calculate_number_of_chars_from_bignum_array(array, 2);

    assert(result == 23);
}


void test_bignum_to_string() {
    uint32_t hex1[] = {0x57656C74, 0x21203132, 0x33202D20, 0x4142433F};
    uint32_t hex0[] = {0x0, 0x0, 0x4861, 0x6C6C6F20};
    bignum n0 = init_bignum(hex0);
    bignum n1 = init_bignum(hex1);
    bignum array[2] = {n0, n1};

    char *expected = "Hallo Welt! 123 - ABC?";
    unsigned char result[23];

    bignum_array_to_string(result, array, 2);

    assert(strcmp((char *)result, expected) == 0);
}


void test_ciphertext_bignum_blocks_to_one_bignum() {
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

    bignum_blocks_to_one_array(result, blocks, 2);

    for (int i = 0; i < 8; i++) {
        assert(result[i] == expected[i]);
    }
}


void test_hamming_weight() {
    uint32_t a_hex[] = {0x0, 0x0, 0x0, 0x123de};
    bignum a = init_bignum(a_hex);

    int result = hamming_weight(a);

    assert(result == 10);
}


void test_polynom_to_bignum() {
    int indices[] = {127, 100, 42, 5, 0};
    int size = 5;
    uint32_t expected[] = {0x80000010, 0x00000000, 0x00000400, 0x00000021};

    bignum n = polynom_to_bignum(indices, size);

    for (int i = 0; i < 4; i++) {
        assert(n.chunks[i] == expected[i]);
    }
}


void assert_hash_key_false() {
    int threshold = 1;
    int number_of_blocks = 2;

    bignum hash_key = init_bignum_to_zero();
    bignum hash_key_copy = copy_bignum(hash_key);

    bignum hash_key_inverse = mult_inverse(hash_key);
    bignum hash_key_inverse_copy = copy_bignum(hash_key_inverse);

    bool result = check_hash_key(threshold, number_of_blocks, hash_key, hash_key_copy, hash_key_inverse, hash_key_inverse_copy);

    assert(!result);
}


void assert_hash_key_true() {
    int threshold = 1;
    int number_of_blocks = 2;

    uint32_t hex[] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    bignum hash_key = init_bignum(hex);
    bignum hash_key_copy = copy_bignum(hash_key);

    bignum hash_key_inverse = mult_inverse(hash_key);
    bignum hash_key_inverse_copy = copy_bignum(hash_key_inverse);

    bool result = check_hash_key(threshold, number_of_blocks, hash_key, hash_key_copy, hash_key_inverse, hash_key_inverse_copy);

    assert(result);
}


void test_one_bit_modification_last_block_one_to_zero() {
    uint32_t hex[] = {0x12300000, 0x00000000, 0x00000000, 0x00000042};
    bignum n = init_bignum(hex);
    uint32_t expected[] = {0x12300000, 0x00000000, 0x00000000, 0x00000040};

    bignum result = one_bit_modification(n, 1);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_one_bit_modification_first_block_zero_to_one() {
    uint32_t hex[] = {0x12300000, 0x00000000, 0x00000000, 0x00000042};
    bignum n = init_bignum(hex);
    uint32_t expected[] = {0x52300000, 0x00000000, 0x00000000, 0x00000042};

    bignum result = one_bit_modification(n, 126);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_average() {
    uint32_t values[10] = {3, 56, 324, 213, 2, 87, 123, 7, 786, 1};
    float expected = 160.2;

    float res = average(values, 10);

    assert(expected == res);
}


void test_standard_deviation() {
    uint32_t values[10] = {3, 56, 324, 213, 2, 87, 123, 7, 786, 1};
    float expected = 231.818375;
    float avg = average(values, 10);

    float res = standard_deviation(values, 10, avg);

    assert(expected == res);
}


void run_tests_util_functions() {
    test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits();
    test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits();
    test_convert_two_32_bit_into_64_bit();
    test_calculate_number_of_bignums_from_string();
    test_calculate_number_of_bignums_from_empty_string();
    test_string_to_bignum();
    test_string_to_bignum_with_empty_string();
    test_calculate_number_of_chars_from_bignum_array();
    test_bignum_to_string();
    test_ciphertext_bignum_blocks_to_one_bignum();
    test_hamming_weight();
    test_polynom_to_bignum();
    assert_hash_key_false();
    assert_hash_key_true();
    test_one_bit_modification_last_block_one_to_zero();
    test_one_bit_modification_first_block_zero_to_one();
    test_average();
    test_standard_deviation();
}
