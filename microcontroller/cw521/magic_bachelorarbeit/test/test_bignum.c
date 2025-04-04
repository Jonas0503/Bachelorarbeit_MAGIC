#ifndef LOCAL
#include "magic_bachelorarbeit/src/bignum.h"
#else
#include "bignum.h"
#endif
#include "assert.h"


void test_init_bignum() {
    uint32_t ahex[] = {0xcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == ahex[i]);
    }
}


void test_init_bignum_array() {
    uint32_t ahex[] = {0xcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c, 0xfd761f7c, 0x2c239ae3, 0x2732819c};

    bignum bignum_array[2];
    init_bignum_array(bignum_array, 2, ahex, 7);

    for (int i = 3; i >= 0; i--) {
        assert(bignum_array[1].chunks[i] == ahex[i+3]);
    }
    for (int i = 6; i >= 4; i--) {
        assert(bignum_array[0].chunks[i-3] == ahex[i-4]);
    }
    assert(bignum_array[0].chunks[0] == 0x0);
}


void test_init_bignum_to_zero() {
    bignum a = init_bignum_to_zero();

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == 0x0);
    }
}


void test_init_bignum_to_one() {
    bignum a = init_bignum_to_one();

    for (int i = 0; i < 3; i++) {
        assert(a.chunks[i] == 0x0);
    }
    assert(a.chunks[3] == 0x1);
}


void test_xor_bignum_different_numbers() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 133845660261761956813865404136431853788
    uint32_t expected[] = {0x64b1bc8b, 0x6c88b09e, 0xb7161fab, 0x3240a0dc};

    bignum a = init_bignum(ahex);
    bignum b = init_bignum(bhex);
    bignum result = xor_bignum(a, b);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_xor_same_numbers_and_overwrite_the_number() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex);

    a = xor_bignum(a, a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == 0x0);
    }
}


void test_is_bignum_not_zero_true() {
    bignum a = init_bignum_to_one();
    assert(is_bignum_not_zero(a));
}


void test_is_bignum_not_zero_false() {
    bignum a = init_bignum_to_zero();
    assert(!is_bignum_not_zero(a));
}


void test_is_bignum_zero_true() {
    bignum a = init_bignum_to_zero();
    assert(!is_bignum_not_zero(a));
}


void test_shift_left_by_one_bignum_no_new_block() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 225592949049619530851197247017359573816
    uint32_t expected[] = {0xa9b79f1f, 0xfaec3ef8, 0x584735c6, 0x4e650338};

    bignum a = init_bignum(ahex);
    bignum result = shift_left_by_one_bignum(a);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_shift_left_by_one_bignum_new_block_and_overwrite_variable() {
    // 170141183460469231731687303715884105728
    uint32_t ahex[] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};
    // 340282366920938463463374607431768211456
    uint32_t expected[] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};

    bignum a = init_bignum(ahex);

    a = shift_left_by_one_bignum(a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == expected[i]);
    }
}


void test_shift_right_by_one() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 56398237262404882712799311754339893454
    uint32_t expected[] = {0x2a6de7c7, 0xfebb0fbe, 0x1611cd71, 0x939940ce};

    bignum a = init_bignum(ahex);
    bignum result = shift_right_by_one_bignum(a);

    for (int i = 0; i < 4; i++) {
        assert(result.chunks[i] == expected[i]);
    }
}


void test_shift_right_by_one_overwrite_variable() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 56398237262404882712799311754339893454
    uint32_t expected[] = {0x2a6de7c7, 0xfebb0fbe, 0x1611cd71, 0x939940ce};

    bignum a = init_bignum(ahex);

    a = shift_right_by_one_bignum(a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == expected[i]);
    }
}


void test_is_bignum_odd_true() {
    // 170141183460469231731687303715884105729
    uint32_t ahex[] = {0x80000000, 0x00000000, 0x00000000, 0x00000001};
    bignum a = init_bignum(ahex);

    bool result = is_bignum_odd(a);

    assert(result);
}


void test_is_bignum_odd_false() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex);

    bool result = is_bignum_odd(a);

    assert(!result);
}


void test_is_bignum_inside_galois_field_true() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0xdbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex);

    bool result = is_bignum_inside_galois_field_after_left_shift(a);

    assert(result);
}


void test_is_bignum_inside_galois_field_false() {
    // 340282366920938463463374607431768211456
    uint32_t ahex[] = {0xf0000000, 0x00000000, 0x00000000, 0x00000000};
    bignum a = init_bignum(ahex);

    bool result = is_bignum_inside_galois_field_after_left_shift(a);

    assert(!result);
}


void test_copy_bignum() {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex);

    bignum b = copy_bignum(a);

    for (int i = 0; i < 4; i++) {
        assert(a.chunks[i] == b.chunks[i]);
    }

    a.chunks[3] = 0x1;
    assert(a.chunks[3] != b.chunks[3]);
    b.chunks[0] = 0x1;
    assert(a.chunks[0] != b.chunks[0]);
}


void test_are_bignums_equal_true() {
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x0, 0x0};
    bignum a = init_bignum(ahex);
    uint32_t bhex[] = {0x54dbcf8f, 0xfd761f7c, 0x0, 0x0};
    bignum b = init_bignum(bhex);

    assert(are_bignums_equal(a, b));
}


void test_are_bignums_equal_false() {
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x0, 0x0};
    bignum a = init_bignum(ahex);
    uint32_t bhex[] = {0x0, 0xfd761f7c, 0x0, 0x1};
    bignum b = init_bignum(bhex);

    assert(!are_bignums_equal(a, b));
}


void run_tests_bignum() {
    test_init_bignum();
    test_init_bignum_array();
    test_init_bignum_to_zero();
    test_init_bignum_to_one();
    test_xor_bignum_different_numbers();
    test_xor_same_numbers_and_overwrite_the_number();
    test_is_bignum_not_zero_true();
    test_is_bignum_not_zero_false();
    test_shift_left_by_one_bignum_no_new_block();
    test_shift_left_by_one_bignum_new_block_and_overwrite_variable();
    test_shift_right_by_one();
    test_shift_right_by_one_overwrite_variable();
    test_is_bignum_odd_true();
    test_is_bignum_odd_false();
    test_is_bignum_inside_galois_field_true();
    test_is_bignum_inside_galois_field_false();
    test_copy_bignum();
    test_are_bignums_equal_true();
    test_are_bignums_equal_false();
}
