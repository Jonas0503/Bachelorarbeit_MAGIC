#include "acutest.h"
#include "bignum.h"


void test_init_bignum(void) {
    uint32_t ahex[] = {0xcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == ahex[3-i]);
    }

    destroy_bignum(a);
}


void test_init_bignum_to_zero(void) {
    bignum a = init_bignum_to_zero();

    TEST_CHECK(a.number_of_chunks == 1);
    TEST_CHECK(a.chunks[0] == 0);

    destroy_bignum(a);
}


void test_set_existing_bignum_to_zero(void) {
    uint32_t ahex[] = {0xcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    set_existing_bignum_to_zero(&a);

    TEST_CHECK(a.number_of_chunks == 1);
    TEST_CHECK(a.chunks[0] == 0);

    destroy_bignum(a);
}


void test_init_bignum_to_one(void) {
    bignum a = init_bignum_to_one();

    TEST_CHECK(a.number_of_chunks == 1);
    TEST_CHECK(a.chunks[0] == 0x1);

    destroy_bignum(a);
}


void test_set_existing_bignum_to_one(void) {
    uint32_t ahex[] = {0xcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    set_existing_bignum_to_one(&a);

    TEST_CHECK(a.number_of_chunks == 1);
    TEST_CHECK(a.chunks[0] == 0x1);

    destroy_bignum(a);
}


void test_xor_bignum_different_numbers(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 64355660103880947803722881228455682368
    uint32_t bhex[] = {0x306a7304, 0x91feafe2, 0x9b358548, 0x15722140};
    // 133845660261761956813865404136431853788
    uint32_t expected[] = {0x64b1bc8b, 0x6c88b09e, 0xb7161fab, 0x3240a0dc};

    bignum a = init_bignum(ahex, 4);
    bignum b = init_bignum(bhex, 4);
    bignum result;

    xor_bignum(&result, false, a, b);

    TEST_CHECK(result.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result.chunks[i] == expected[3-i]);
    }

    destroy_bignum(a);
    destroy_bignum(b);
    destroy_bignum(result);
}


void test_xor_same_numbers_and_overwrite_the_number(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    xor_bignum(&a, true, a, a);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == 0x0);
    }

    destroy_bignum(a);
}


void test_is_bignum_not_zero_true(void) {
    bignum a = init_bignum_to_one();
    TEST_CHECK(is_bignum_not_zero(a));

    destroy_bignum(a);
}


void test_is_bignum_not_zero_false(void) {
    bignum a = init_bignum_to_zero();
    TEST_CHECK(!is_bignum_not_zero(a));

    destroy_bignum(a);
}


void test_shift_left_by_one_bignum_no_new_block(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 225592949049619530851197247017359573816
    uint32_t expected[] = {0xa9b79f1f, 0xfaec3ef8, 0x584735c6, 0x4e650338};

    bignum a = init_bignum(ahex, 4);
    bignum result;

    shift_left_by_one_bignum(&result, false, a);

    TEST_CHECK(result.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result.chunks[i] == expected[3-i]);
    }

    destroy_bignum(a);
    destroy_bignum(result);
}


void test_shift_left_by_one_bignum_new_block_and_overwrite_variable(void) {
    // 170141183460469231731687303715884105728
    uint32_t ahex[] = {0x80000000, 0x00000000, 0x00000000, 0x00000000};
    // 340282366920938463463374607431768211456
    uint32_t expected[] = {0x1, 0x00000000, 0x00000000, 0x00000000, 0x00000000};

    bignum a = init_bignum(ahex, 4);

    shift_left_by_one_bignum(&a, true, a);

    TEST_CHECK(a.number_of_chunks == 5);
    for (int i = 0; i < 5; i++) {
        TEST_CHECK(a.chunks[i] == expected[4-i]);
    }

    destroy_bignum(a);
}


void test_shift_right_by_one(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 56398237262404882712799311754339893454
    uint32_t expected[] = {0x2a6de7c7, 0xfebb0fbe, 0x1611cd71, 0x939940ce};

    bignum a = init_bignum(ahex, 4);
    bignum result;

    shift_right_by_one_bignum(&result, false, a);

    TEST_CHECK(result.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(result.chunks[i] == expected[3-i]);
    }

    destroy_bignum(a);
    destroy_bignum(result);
}


void test_shift_right_by_one_overwrite_variable(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 56398237262404882712799311754339893454
    uint32_t expected[] = {0x2a6de7c7, 0xfebb0fbe, 0x1611cd71, 0x939940ce};

    bignum a = init_bignum(ahex, 4);

    shift_right_by_one_bignum(&a, true, a);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < 4; i++) {
        TEST_CHECK(a.chunks[i] == expected[3-i]);
    }

    destroy_bignum(a);
}


void test_shift_right_by_x(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 25646948989744888746281190
    uint32_t expected[] = {0x1536f3, 0xe3ff5d87, 0xdf0b08e6};

    bignum a = init_bignum(ahex, 4);
    bignum result;

    shift_right_by_x_bignum(&result, false, a, 42);

    TEST_CHECK(result.number_of_chunks == 4);
    for (int i = 0; i < 3; i++) {
        TEST_CHECK(result.chunks[i] == expected[2-i]);
    }

    destroy_bignum(a);
    destroy_bignum(result);
}


void test_shift_right_by_x_overwriting_variable(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    // 25646948989744888746281190
    uint32_t expected[] = {0x1536f3, 0xe3ff5d87, 0xdf0b08e6};

    bignum a = init_bignum(ahex, 4);

    shift_right_by_x_bignum(&a, true, a, 42);

    TEST_CHECK(a.number_of_chunks == 4);
    for (int i = 0; i < 3; i++) {
        TEST_CHECK(a.chunks[i] == expected[2-i]);
    }

    destroy_bignum(a);
}


void test_is_bignum_odd_true(void) {
    // 170141183460469231731687303715884105729
    uint32_t ahex[] = {0x80000000, 0x00000000, 0x00000000, 0x00000001};
    bignum a = init_bignum(ahex, 4);

    bool result = is_bignum_odd(a);

    TEST_CHECK(result);

    destroy_bignum(a);
}


void test_is_bignum_odd_false(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    bool result = is_bignum_odd(a);

    TEST_CHECK(!result);

    destroy_bignum(a);
}


void test_is_bignum_inside_galois_field_true(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    bool result = is_bignum_inside_galois_field(a, 128);

    TEST_CHECK(result);

    destroy_bignum(a);
}


void test_is_bignum_inside_galois_field_false(void) {
    // 340282366920938463463374607431768211456
    uint32_t ahex[] = {0x1, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
    bignum a = init_bignum(ahex, 5);

    bool result = is_bignum_inside_galois_field(a, 128);

    TEST_CHECK(!result);

    destroy_bignum(a);
}


void test_copy_bignum(void) {
    // 112796474524809765425598623508679786908
    uint32_t ahex[] = {0x54dbcf8f, 0xfd761f7c, 0x2c239ae3, 0x2732819c};
    bignum a = init_bignum(ahex, 4);

    bignum b = copy_bignum(a);

    TEST_CHECK(a.number_of_chunks == b.number_of_chunks);
    for (int i = 0; i < a.number_of_chunks; i++) {
        TEST_CHECK(a.chunks[i] == b.chunks[i]);
    }

    a.chunks[3] = 0x1;
    TEST_CHECK(a.chunks[3] != b.chunks[3]);
    b.chunks[0] = 0x1;
    TEST_CHECK(a.chunks[0] != b.chunks[0]);

    destroy_bignum(a);
    destroy_bignum(b);
}


TEST_LIST = {
    {"test_init_bignum", test_init_bignum},
    {"init_bignum_to_zero", test_init_bignum_to_zero},
    {"set_existing_bignum_to_zero", test_set_existing_bignum_to_zero},
    {"init_bignum_to_one", test_init_bignum_to_one},
    {"set_existing_bignum_to_one", test_set_existing_bignum_to_one},
    {"xor_bignum_different_numbers", test_xor_bignum_different_numbers},
    {"xor_same_numbers_and_overwrite_the_number", test_xor_same_numbers_and_overwrite_the_number},
    {"is_bignum_not_zero_true", test_is_bignum_not_zero_true},
    {"is_bignum_not_zero_false", test_is_bignum_not_zero_false},
    {"shift_left_by_one_bignum_no_new_block", test_shift_left_by_one_bignum_no_new_block},
    {"shift_left_by_one_bignum_new_block_and_overwrite_variable", test_shift_left_by_one_bignum_new_block_and_overwrite_variable},
    {"shift_right_by_one", test_shift_right_by_one},
    {"shift_right_by_one_overwrite_variable", test_shift_right_by_one_overwrite_variable},
    {"shift_right_by_x", test_shift_right_by_x},
    {"shift_right_by_x_overwriting_variable", test_shift_right_by_x_overwriting_variable},
    {"is_bignum_odd_true", test_is_bignum_odd_true},
    {"is_bignum_odd_false", test_is_bignum_odd_false},
    {"is_bignum_inside_galois_field_true", test_is_bignum_inside_galois_field_true},
    {"is_bignum_inside_galois_field_false", test_is_bignum_inside_galois_field_false},
    {"copy_bignum", test_copy_bignum},
    {NULL, NULL}
};
