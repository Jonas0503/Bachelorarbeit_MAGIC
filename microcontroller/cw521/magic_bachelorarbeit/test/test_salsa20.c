#include "acutest.h"
#include "salsa20.h"
#include "bignum.h"

#include "stdbool.h"


// Test values from:
// https://cr.yp.to/snuffle/spec.pdf (official paper)
// https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors


// --------------------------- start: helper functions in this test file ---------------------------

bool are_states_equal(uint32_t state1[16], uint32_t state2[16]) {
    for (int i = 0; i < 16; i++) {
        if (state1[i] != state2[i]) return false;
    }

    return true;
}


bool are_messages_equal(uint32_t *ciphertext, u_int32_t *expected, uint64_t message_length, int stream_start) {
    for (uint64_t i = 0; i < message_length; i++) {
        if (ciphertext[i+stream_start] != expected[i]) return false;
    }

    return true;
}


// --------------------------- end: helper functions in this test file ---------------------------


void test_shift_left_and_rotate(void) {
    // my test value
    uint32_t expected = 0xA194C67E;
    uint32_t result = shift_left_and_rotate(0xd43298cf, 3);

    TEST_CHECK(result == expected);
}


void test_quarterround_1(void) {
    uint32_t a, b, c, d;
    a = 0x0;
    b = 0x0;
    c = 0x0;
    d = 0x0;

    quarterround(&a, &b, &c, &d);

    TEST_CHECK(a == 0x0);
    TEST_CHECK(b == 0x0);
    TEST_CHECK(c == 0x0);
    TEST_CHECK(d == 0x0);
}


void test_quarterround_2(void) {
    uint32_t a, b, c, d;
    a = 0xe7e8c006;
    b = 0xc4f9417d;
    c = 0x6479b4b2;
    d = 0x68c67137;

    quarterround(&a, &b, &c, &d);

    TEST_CHECK(a == 0xe876d72b);
    TEST_CHECK(b == 0x9361dfd5);
    TEST_CHECK(c == 0xf1460244);
    TEST_CHECK(d == 0x948541a3);
}


void test_rowround_1(void) {
    uint32_t state[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000
    };

    uint32_t state_expected[16] = {
        0x08008145, 0x00000080, 0x00010200, 0x20500000,
        0x20100001, 0x00048044, 0x00000080, 0x00010000,
        0x00000001, 0x00002000, 0x80040000, 0x00000000,
        0x00000001, 0x00000200, 0x00402000, 0x88000100
    };

    rowround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_rowround_2(void) {
    uint32_t state[16] = {
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
    };

    uint32_t state_expected[16] = {
        0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
        0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
        0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
        0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d
    };

    rowround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_columnround_1(void) {
    uint32_t state[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000
    };

    uint32_t state_expected[16] = {
        0x10090288, 0x00000000, 0x00000000, 0x00000000,
        0x00000101, 0x00000000, 0x00000000, 0x00000000,
        0x00020401, 0x00000000, 0x00000000, 0x00000000,
        0x40a04001, 0x00000000, 0x00000000, 0x00000000
    };

    columnround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_columnround_2(void) {
    uint32_t state[16] = {
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
    };

    uint32_t state_expected[16] = {
        0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
        0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
        0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
        0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8
    };

    columnround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_doubleround_1(void) {
    uint32_t state[16] = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };

    uint32_t state_expected[16] = {
        0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
        0x08000090, 0x02402200, 0x00004000, 0x00800000,
        0x00010200, 0x20400000, 0x08008104, 0x00000000,
        0x20500000, 0xa0000040, 0x0008180a, 0x612a8020
    };

    doubleround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_doubleround_2(void) {
    uint32_t state[16] = {
        0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
        0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
        0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
        0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1
    };

    uint32_t state_expected[16] = {
        0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
        0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
        0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
        0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277
    };

    doubleround(state);

    TEST_CHECK(are_states_equal(state, state_expected));
}


void test_littleendian_1(void) {
    uint32_t input = 0x564b1e09;
    uint32_t expected = 0x091e4b56;

    uint32_t result = littleendian(input);

    TEST_CHECK(result == expected);
}


void test_littleendian_2(void) {
    uint32_t input = 0xfffffffa;
    uint32_t expected = 0xfaffffff;

    uint32_t result = littleendian(input);

    TEST_CHECK(result == expected);
}


void test_salsa20_hash(void) {
    uint32_t state_in[16] = {
        0xd39f0d73, 0x4c3752b7, 0x0375de25, 0xbfbbea88,
        0x31edb330, 0x016ab2db, 0xafc7a630, 0x5610b3cf,
        0x1ff0203f, 0x0f535da1, 0x74933071, 0xee37cc24,
        0x4fc9eb4f, 0x03519c2f, 0xcb1af4f3, 0x58766836
    };

    uint32_t expected[16] = {
        0x6d2ab2a8, 0x9cf0f8ee, 0xa8c4becb, 0x1a6eaa9a,
        0x1d1d961a, 0x961eebf9, 0xbea3fb30, 0x45903339,
        0x7628989d, 0xb4391b5e, 0x6b2aec23, 0x1b6f7272,
        0xdbece887, 0x6f9b6e12, 0x18e85f9e, 0xb31330ca
    };

    uint32_t result[16];

    salsa20_hash(state_in, result);

    TEST_CHECK(are_states_equal(result, expected));
}


void test_salsa20_expansion(void) {
    uint32_t key[8] = {
        0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
        0xc9cacbcc, 0xcdcecfd0, 0xd1d2d3d4, 0xd5d6d7d8
    };

    uint32_t nonce[4] = {
        0x65666768, 0x696a6b6c,
        0x6d6e6f70, 0x71727374
    };

    uint32_t expected[16] = {
        0x45254427, 0x290f6bc1, 0xff8b7a06, 0xaae9d962,
        0x5990b66a, 0x1533c841, 0xef31de22, 0xd772287e,
        0x68c507e1, 0xc5991f02, 0x664e4cb0, 0x54f5f6b8,
        0xb1a08582, 0x06489577, 0xc0c384ec, 0xea67f64a
    };

    uint32_t state[16];
    uint32_t result[16];

    salsa20_expansion(state, result, key, nonce);

    TEST_CHECK(are_states_equal(result, expected));
}

// https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors#L13
// (von GitHub) Set 1, vector#  0:
void test_salsa20_encryption_decryption_1(void) {
    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    uint32_t nonce[2] = {0x0};
    uint32_t plaintext[128] = {0x0};
    uint32_t ciphertext[128];

    uint32_t expected_1[16] = {
        0xE3BE8FDD, 0x8BECA2E3, 0xEA8EF947, 0x5B29A6E7,
        0x003951E1, 0x097A5C38, 0xD23B7A5F, 0xAD9F6844,
        0xB22C9755, 0x9E2723C7, 0xCBBD3FE4, 0xFC8D9A07,
        0x44652A83, 0xE72A9C46, 0x1876AF4D, 0x7EF1A117
    };

    uint32_t expected_2[16] = {
        0x958211C4, 0xBA2EBD58, 0x38C635ED, 0xB81F513A,
        0x91A294E1, 0x94F1C039, 0xAEEC657D, 0xCE40AA7E,
        0x7C0AF57C, 0xACEFA40C, 0x9F14B71A, 0x4B3456A6,
        0x3E162EC7, 0xD8D10B8F, 0xFB1810D7, 0x1001B618
    };

    salsa20_encryption_decryption(key, nonce, plaintext, ciphertext, 128);

    TEST_CHECK(are_messages_equal(ciphertext, expected_1, 16, 0));
    TEST_CHECK(are_messages_equal(ciphertext, expected_2, 16, 64));

    // Decryption
    uint32_t result_decryption[128];
    uint32_t result_decryption_expected[128] = {0x0};

    salsa20_encryption_decryption(key, nonce, ciphertext, result_decryption, 128);
    TEST_CHECK(are_messages_equal(result_decryption, result_decryption_expected, 128, 0));
}


// https://github.com/das-labor/legacy/blob/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors#L2119
// (von GitHub) Set 3, vector#234:
void test_salsa20_encryption_decryption_2(void) {
    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0};
    uint32_t plaintext[128] = {0x0};
    uint32_t ciphertext[128];

    uint32_t expected_1[16] = {
        0x2D226C11, 0xF47B3C0C, 0xCD0959B6, 0x1F59D5CC,
        0x30FCEF6D, 0xBB8CBB3D, 0xCC1CC252, 0x04FCD449,
        0x8C37426A, 0x63BEA328, 0x2B1A8A0D, 0x60E13EB2,
        0xFE59241A, 0x9F6AF426, 0x689866ED, 0xC769E1E6
    };

    uint32_t expected_2[16] = {
        0x0597188A, 0x1C192557, 0x69BE1C21, 0x0399AD17,
        0x2EB46C52, 0xF92FD541, 0xDF2EAD71, 0xB1FF8EA7,
        0xADD380EC, 0x71A5FD7A, 0xDB5181EA, 0xDD1825EC,
        0x02779A45, 0x09BE5832, 0x708CA283, 0x6C1693A5
    };

    // Encryption
    salsa20_encryption_decryption(key, nonce, plaintext, ciphertext, 128);
    TEST_CHECK(are_messages_equal(ciphertext, expected_1, 16, 48));
    TEST_CHECK(are_messages_equal(ciphertext, expected_2, 16, 112));

    // Decryption
    uint32_t result_decryption[128];
    uint32_t result_decryption_expected[128] = {0x0};

    salsa20_encryption_decryption(key, nonce, ciphertext, result_decryption, 128);
    TEST_CHECK(are_messages_equal(result_decryption, result_decryption_expected, 128, 0));
}


void test_plaintext_to_blocks_and_back_to_plaintext(void) {
    char *text = "Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!Hallo Welt!";
    uint32_t key[8] = {
        0x80000000, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };
    uint32_t nonce[2] = {0x0};

    const int number_of_blocks = calculate_number_of_bignums_from_string(text);
    bignum ciphertext_blocks[number_of_blocks];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, text, key, nonce);

    const int number_of_chars = calculate_number_of_chars_from_bignum_array(ciphertext_blocks, number_of_blocks);
    unsigned char plaintext[number_of_chars];
    ciphertext_blocks_to_plaintext_as_str(plaintext, ciphertext_blocks, number_of_blocks, key, nonce);

    TEST_CHECK(strcmp(text, (char *)plaintext) == 0);
}


TEST_LIST = {
    {"shift_left_and_rotate", test_shift_left_and_rotate},
    {"quarterround_1", test_quarterround_1},
    {"quarterround_2", test_quarterround_2},
    {"rowround_1", test_rowround_1},
    {"rowround_2", test_rowround_2},
    {"columnround_1", test_columnround_1},
    {"columnround_2", test_columnround_2},
    {"doubleround_1", test_doubleround_1},
    {"doubleround_2", test_doubleround_2},
    {"littleendian_1", test_littleendian_1},
    {"littleendian_2", test_littleendian_2},
    {"salsa20_hash", test_salsa20_hash},
    {"salsa20_expansion", test_salsa20_expansion},
    {"salsa20_encryption_decryption_1", test_salsa20_encryption_decryption_1},
    {"salsa20_encryption_decryption_2", test_salsa20_encryption_decryption_2},
    {"plaintext_to_blocks_and_back_to_plaintext", test_plaintext_to_blocks_and_back_to_plaintext},
    {NULL, NULL}
};
