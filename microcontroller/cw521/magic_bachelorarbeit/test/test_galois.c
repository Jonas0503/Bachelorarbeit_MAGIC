#ifndef LOCAL
#include "magic_bachelorarbeit/src/galois.h"
#else
#include "galois.h"
#endif
#include "assert.h"


void test_irreducible_polynom_128() {
    // With "extern" I can use the const IRREDUCIBLE_POLYNOMIAL_128 in this file
    extern const bignum IRREDUCIBLE_POLYNOMIAL_128;
    bignum polynom = IRREDUCIBLE_POLYNOMIAL_128;

    assert(polynom.chunks[3] == 0x00000087);
    assert(polynom.chunks[2] == 0x00000000);
    assert(polynom.chunks[1] == 0x00000000);
    assert(polynom.chunks[0] == 0x00000000);
}


void test_add_sub_two_different_numbers() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 133845660261761956813865404136431853788
    uint32_t expected[] = {0x64b1bc8b, 0x6c88b09e, 0xb7161fab, 0x3240a0dc};

    bignum a = init_bignum(ahex);
    bignum b = init_bignum(bhex);

    bignum result_add = add(a, b);

    for (int i = 0; i < 4; i++) {
        assert(result_add.chunks[i] == expected[i]);
    }
}


void test_add_same_numbers_and_overwrite_the_number() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};

    bignum a = init_bignum(ahex);

    a = add(a, a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == 0x0);
    }
}


void test_mult_two_different_numbers() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 272764754479577719205539380006796958445
    uint32_t expected[] = {0xcd3494b2, 0x192d4c17, 0x4fe2e431, 0xef889aed};

    bignum a = init_bignum(ahex);
    bignum b = init_bignum(bhex);
    bignum result = mult(a, b);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_mult_same_numbers_and_overwrite_the_number() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 333683291628008625591354273616078342104
    uint32_t expected[] = {0xfb091077, 0xda4ebf05, 0x0628e468, 0xec2087d8};

    bignum a = init_bignum(ahex);

    a = mult(a, a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == expected[i]);
    }
}


void test_mult_inverse() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 41136419426691436761356546764598741865
    uint32_t expected[] = {0x1ef29611, 0x1058e3e3, 0x10cc8e7a, 0xd57d0b69};

    bignum a = init_bignum(ahex);
    bignum result = mult_inverse(a);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_mult_inverse_with_overwriting_the_number() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 41136419426691436761356546764598741865
    uint32_t expected[] = {0x1ef29611, 0x1058e3e3, 0x10cc8e7a, 0xd57d0b69};

    bignum a = init_bignum(ahex);

    a = mult_inverse(a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == expected[i]);
    }
}

void run_tests_galois() {
    test_irreducible_polynom_128();
    test_add_sub_two_different_numbers();
    test_add_same_numbers_and_overwrite_the_number();
    test_mult_two_different_numbers();
    test_mult_same_numbers_and_overwrite_the_number();
    test_mult_inverse();
    test_mult_inverse_with_overwriting_the_number();
}
