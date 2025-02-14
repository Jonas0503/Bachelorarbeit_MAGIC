#include "acutest.h"
#include "util.h"


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


TEST_LIST = {
    {"convert_64_bit_into_two_32_bit_a_is_less_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_less_than_32_bits},
    {"convert_64_bit_into_two_32_bit_a_is_more_than_32_bits", test_convert_64_bit_into_two_32_bit_a_is_more_than_32_bits},
    {"convert_two_32_bit_into_64_bit", test_convert_two_32_bit_into_64_bit},
    {NULL, NULL}
};
