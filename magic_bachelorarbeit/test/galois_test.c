#include "acutest.h"
#include "galois.h"


void test_init_irreducible_polynom_128(void) {
    bignum polynom = init_irreducible_polynom_128();

    TEST_CHECK(polynom.number_of_chunks == 5);
    TEST_CHECK(polynom.chunks[0] == 0x00000087);
    TEST_CHECK(polynom.chunks[1] == 0x00000000);
    TEST_CHECK(polynom.chunks[2] == 0x00000000);
    TEST_CHECK(polynom.chunks[3] == 0x00000000);
    TEST_CHECK(polynom.chunks[4] == 0x1);

    destroy_bignum(polynom);
}


void test_add_sub_two_different_numbers(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 133845660261761956813865404136431853788
    uint32_t expected[] = {0x64b1bc8b, 0x6c88b09e, 0xb7161fab, 0x3240a0dc};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum result_add, result_sub;

    add(&result_add, false, a, b);
    add(&result_sub, false, a, b);

    TEST_CHECK(result_add.number_of_chunks == 4);
    TEST_CHECK(result_sub.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result_add.chunks[i] == expected[3 - i]);
        TEST_CHECK(result_sub.chunks[i] == expected[3 - i]);
    }

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(result_add);
    destroy_bignum(result_sub);
}


void test_add_same_numbers_and_overwrite_the_number(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};

    bignum a = init_bignum(ahex, 4);

    add(&a, true, a, a);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == 0x0);
    }

    destroy_bignum(a);
}


void test_mult_two_different_numbers(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 272764754479577719205539380006796958445
    uint32_t expected[] = {0xcd3494b2, 0x192d4c17, 0x4fe2e431, 0xef889aed};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum polynom = init_irreducible_polynom_128();
    bignum result;

    mult(&result, false, a, b, polynom, 128);

    TEST_CHECK(result.number_of_chunks == 5);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result.chunks[i] == expected[3 - i]);
    }
    TEST_CHECK(result.chunks[4] == 0);

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(result);
    destroy_bignum(polynom);
}


void test_mult_same_numbers_and_overwrite_the_number(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 333683291628008625591354273616078342104
    uint32_t expected[] = {0xfb091077, 0xda4ebf05, 0x0628e468, 0xec2087d8};

    bignum a = init_bignum(ahex, 4);
    bignum polynom = init_irreducible_polynom_128();

    mult(&a, true, a, a, polynom, 128);

    TEST_CHECK(a.number_of_chunks == 5);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == expected[3 - i]);
    }
    TEST_CHECK(a.chunks[4] == 0);

    destroy_bignum(a);
    destroy_bignum(polynom);
}


void test_mult_inverse(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 41136419426691436761356546764598741865
    uint32_t expected[] = {0x1ef29611, 0x1058e3e3, 0x10cc8e7a, 0xd57d0b69};

    bignum a = init_bignum(ahex, 4);
    bignum polynom = init_irreducible_polynom_128();
    bignum result;

    mult_inverse(&result, false, a, polynom, 128);

    TEST_CHECK(result.number_of_chunks == 5);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result.chunks[i] == expected[3 - i]);
    }
    TEST_CHECK(result.chunks[4] == 0);

    destroy_bignum(a);
    destroy_bignum(polynom);
    destroy_bignum(result);
}


void test_mult_inverse_with_overwriting_the_number(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 41136419426691436761356546764598741865
    uint32_t expected[] = {0x1ef29611, 0x1058e3e3, 0x10cc8e7a, 0xd57d0b69};

    bignum a = init_bignum(ahex, 4);
    bignum polynom = init_irreducible_polynom_128();

    mult_inverse(&a, true, a, polynom, 128);

    TEST_CHECK(a.number_of_chunks == 5);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == expected[3 - i]);
    }
    TEST_CHECK(a.chunks[4] == 0);

    destroy_bignum(a);
    destroy_bignum(polynom);
}


TEST_LIST = {
    {"init_irreducible_polynom_128", test_init_irreducible_polynom_128},
    {"add_sub_two_different_numbers", test_add_sub_two_different_numbers},
    {"test_add_same_numbers_and_overwrite_the_number", test_add_same_numbers_and_overwrite_the_number},
    {"mult_two_different_numbers", test_mult_two_different_numbers},
    {"mult_same_numbers_and_overwrite_the_number", test_mult_same_numbers_and_overwrite_the_number},
    {"mult_inverse", test_mult_inverse},
    {"mult_inverse_with_overwriting_the_number", test_mult_inverse_with_overwriting_the_number},
    {NULL, NULL}
};
