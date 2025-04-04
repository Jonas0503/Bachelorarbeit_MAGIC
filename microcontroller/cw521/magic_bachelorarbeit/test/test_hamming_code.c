#ifndef LOCAL
#include "magic_bachelorarbeit/src/hamming_code.h"
#include "magic_bachelorarbeit/src/util_functions.h"
#include "magic_bachelorarbeit/src/salsa20.h"
#else
#include "hamming_code.h"
#include "util_functions.h"
#include "salsa20.h"
#endif
#include "stdio.h"
#include "assert.h"


void test_calculate_number_of_ciphertext_blocks_with_parity_per_block_from_string() {
    char *text = "Hallo WeltABC123";
    int expected = 2;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(text);

    assert(expected == result);
}


void test_calculate_number_of_ciphertext_blocks_with_parity_per_block_from_string_two_blocks() {
    char *text = "Hallo WeltABC123J";
    int expected = 3;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(text);

    assert(expected == result);
}


void test_calculate_number_of_ciphertext_blocks_with_parity_all_blocks_from_string_1() {
    char *text = "Hallo WeltABC123";
    int expected = 2;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(text);

    assert(expected == result);
}


void test_calculate_number_of_ciphertext_blocks_with_parity_all_blocks_from_string_2() {
    char *text = "Hallo WeltABC123Hallo WeltABC123";
    int expected = 3;

    int result = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(text);

    assert(expected == result);
}


void test_bignums_to_bit_arrays_with_space_for_parity_bits_per_block() {
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
    bignums_to_bit_arrays_with_space_for_parity_bits_per_block(result, ciphertext_blocks, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            assert(expected[i][k] == result[i][k]);
        }
    }
}


void test_bignums_to_bit_arrays_with_space_for_parity_bits_all_blocks() {
    uint32_t hex[4] = {0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum blocks_no_parity[1];
    init_bignum_array(blocks_no_parity, 1, hex, 4);

    int number_of_blocks = 1;
    int number_of_blocks_with_parity = 2;

    bool expected[2][128] = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        },
        {
            0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0,
            0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1,
            1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0,
            0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1
        }
    };

    bool result[number_of_blocks_with_parity][128];
    bignums_to_bit_arrays_with_space_for_parity_bits_all_blocks(result, blocks_no_parity, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            assert(expected[i][k] == result[i][k]);
        }
    }
}


void test_set_parity_bits_per_block() {
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
    set_parity_bits_per_block(result, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            assert(expected[i][k] == result[i][k]);
        }
    }
}


void test_set_parity_bits_all_blocks() {
    int number_of_blocks_with_parity = 2;

    bool expected[2][128] = {
        {
            0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        },
        {
            1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0,
            0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1,
            1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0,
            0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1
        }
    };

    bool result[2][128] = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        },
        {
            0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0,
            0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1,
            1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0,
            0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1
        }
    };
    set_parity_bits_all_blocks(result, number_of_blocks_with_parity);

    for (int i = 0; i < number_of_blocks_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            assert(expected[i][k] == result[i][k]);
        }
    }
}


void test_bit_arrays_to_bignum_array() {
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
        assert(are_bignums_equal(expected[i], result[i]));
    }
}


void test_add_parity_per_block_to_bignum_array() {
    int number_of_blocks = 1;
    int number_of_blocks_with_parity = 2;

    uint32_t hex_ciphertext[4] = {0xa0ba8f54, 0x1c67d2e5, 0xb3f27aa0, 0xbeeeae3c};
    bignum ciphertext_blocks[1] = {init_bignum(hex_ciphertext)};

    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum expected[2];
    init_bignum_array(expected, 2, hex, 8);

    bignum result[number_of_blocks_with_parity];
    add_parity_per_block_to_bignum_array(result, ciphertext_blocks, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(expected[i], result[i]));
    }
}


void test_add_parity_all_blocks_to_bignum_array() {
    int number_of_blocks = 1;
    int number_of_blocks_with_parity = 2;

    uint32_t hex[4] = {0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum blocks_no_parity[1];
    init_bignum_array(blocks_no_parity, 1, hex, 4);

    uint32_t hex_expected[8] = {0x28800000, 0x00000000, 0x00000000, 0x00000001, 0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum expected[2];
    init_bignum_array(expected, 2, hex_expected, 8);

    bignum result[number_of_blocks_with_parity];
    add_parity_all_blocks_to_bignum_array(result, blocks_no_parity, number_of_blocks, number_of_blocks_with_parity);

    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(expected[i], result[i]));
    }
}


void test_bignum_array_to_bit_arrays() {
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
            assert(expected[i][k] == result[i][k]);
        }
    }
}


void test_verify_hamming_code_per_block_two_bit_error_in_one_block() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[0] = one_bit_modification(blocks_parity[0], 100);

    hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);

    assert(!res.correction_successful);
    assert(!res.one_bit_error);
    assert(res.two_bit_error);
    for (int i = 0; i < number_of_bignums_parity; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity[i]));
    }
}


void test_verify_hamming_code_per_block_one_bit_error_in_one_block() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_per_block_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);

    hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);

    assert(res.correction_successful);
    assert(res.one_bit_error);
    assert(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity_correct[i]));
    }
}


void test_verify_hamming_code_per_block_no_error() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);

    assert(res.correction_successful);
    assert(!res.one_bit_error);
    assert(!res.two_bit_error);
    for (int i = 0; i < number_of_bignums_parity; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity[i]));
    }
}


void test_verify_hamming_code_per_block_two_bit_error_in_two_blocks() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[0] = one_bit_modification(blocks_parity[0], 100);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 33);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 45);

    hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);

    assert(!res.correction_successful);
    assert(!res.one_bit_error);
    assert(res.two_bit_error);
    for (int i = 0; i < number_of_bignums_parity; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity[i]));
    }
}


void test_verify_hamming_code_per_block_one_bit_error_in_two_blocks() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_per_block_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_per_block_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_per_block_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 42);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 110);

    hc_result res = verify_hamming_code_per_block(blocks_parity, number_of_bignums_parity);

    assert(res.correction_successful);
    assert(res.one_bit_error);
    assert(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity_correct[i]));
    }
}


void test_verify_hamming_code_all_blocks_no_error() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_all_blocks_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    hc_result res = verify_hamming_code_all_blocks(blocks_parity, number_of_bignums_parity);

    assert(res.correction_successful);
    assert(!res.one_bit_error);
    assert(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity[i]));
    }
}


void test_verify_hamming_code_all_blocks_one_bit_error() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_all_blocks_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_all_blocks_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[1] = one_bit_modification(blocks_parity[1], 42);

    hc_result res = verify_hamming_code_all_blocks(blocks_parity, number_of_bignums_parity);

    assert(res.correction_successful);
    assert(res.one_bit_error);
    assert(!res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity_correct[i]));
    }
}


void test_verify_hamming_code_all_blocks_two_bit_error() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    bignum blocks_parity[number_of_bignums_parity];
    bignum blocks_parity_correct[number_of_bignums_parity];
    add_parity_all_blocks_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);
    add_parity_all_blocks_to_bignum_array(blocks_parity_correct, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    blocks_parity[0] = one_bit_modification(blocks_parity[0], 31);
    blocks_parity[1] = one_bit_modification(blocks_parity[1], 42);

    hc_result res = verify_hamming_code_all_blocks(blocks_parity, number_of_bignums_parity);

    assert(!res.correction_successful);
    assert(!res.one_bit_error);
    assert(res.two_bit_error);
    for (int i = 0; i < 2; i++) {
        assert(are_bignums_equal(res.ciphertext_blocks_with_parity[i], blocks_parity[i]));
    }
}


void test_remove_parity_per_block_from_encrypted_ciphertext_blocks() {
    uint32_t hex_expected[4] = {0xa0ba8f54, 0x1c67d2e5, 0xb3f27aa0, 0xbeeeae3c};
    bignum expected[1] = {init_bignum(hex_expected)};

    uint32_t hex[8] = {0xa0000000, 0x00000000, 0x00000000, 0x000000a0, 0x53d43d50, 0xb8cfa5cb, 0xb3f27aa0, 0xbeeeae3c};
    bignum array[2];
    init_bignum_array(array, 2, hex, 8);

    bignum result[1];
    remove_parity_per_block_from_encrypted_ciphertext_blocks(result, array, 2, 1);

    assert(are_bignums_equal(result[0], expected[0]));
}


void test_remove_parity_all_blocks_from_encrypted_ciphertext_blocks() {
    uint32_t hex[4] = {0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum expected[1];
    init_bignum_array(expected, 1, hex, 4);

    uint32_t hex_parity[8] = {0x28800000, 0x00000000, 0x00000000, 0x00000001, 0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum parity[2];
    init_bignum_array(parity, 2, hex_parity, 8);

    bignum result[1];
    remove_parity_all_blocks_from_encrypted_ciphertext_blocks(result, parity, 2, 1);

    assert(are_bignums_equal(result[0], expected[0]));
}


void run_tests_hamming_code() {
    test_calculate_number_of_ciphertext_blocks_with_parity_per_block_from_string();
    test_calculate_number_of_ciphertext_blocks_with_parity_per_block_from_string_two_blocks();
    test_calculate_number_of_ciphertext_blocks_with_parity_all_blocks_from_string_1();
    test_calculate_number_of_ciphertext_blocks_with_parity_all_blocks_from_string_2();
    test_bignums_to_bit_arrays_with_space_for_parity_bits_per_block();
    test_bignums_to_bit_arrays_with_space_for_parity_bits_all_blocks();
    test_set_parity_bits_per_block();
    test_set_parity_bits_all_blocks();
    test_bit_arrays_to_bignum_array();
    test_add_parity_all_blocks_to_bignum_array();
    test_bignum_array_to_bit_arrays();
    test_verify_hamming_code_per_block_two_bit_error_in_one_block();
    test_verify_hamming_code_per_block_one_bit_error_in_one_block();
    test_verify_hamming_code_per_block_no_error();
    test_verify_hamming_code_per_block_two_bit_error_in_two_blocks();
    test_verify_hamming_code_per_block_one_bit_error_in_two_blocks();
    test_verify_hamming_code_all_blocks_no_error();
    test_verify_hamming_code_all_blocks_one_bit_error();
    test_verify_hamming_code_all_blocks_two_bit_error();
    test_remove_parity_per_block_from_encrypted_ciphertext_blocks();
    test_remove_parity_all_blocks_from_encrypted_ciphertext_blocks();
}