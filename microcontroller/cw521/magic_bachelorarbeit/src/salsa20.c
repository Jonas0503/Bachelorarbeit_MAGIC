#include "salsa20.h"
#include "util_functions.h"

#include "stdio.h"


// implementation based upon the official specification: https://cr.yp.to/snuffle/spec.pdf


uint32_t shift_left_and_rotate(uint32_t value, int number_of_shifts) {
    return (value << number_of_shifts) | (value >> (32 - number_of_shifts));
}


void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    // get the actual values
    uint32_t a_value = *(a);
    uint32_t b_value = *(b);
    uint32_t c_value = *(c);
    uint32_t d_value = *(d);

    // the salsa operations
    b_value ^= shift_left_and_rotate(a_value + d_value, 7);
    c_value ^= shift_left_and_rotate(b_value + a_value, 9);
    d_value ^= shift_left_and_rotate(c_value + b_value, 13);
    a_value ^= shift_left_and_rotate(d_value + c_value, 18);

    // write the updated values back
    *(a) = a_value;
    *(b) = b_value;
    *(c) = c_value;
    *(d) = d_value;
}


void rowround(uint32_t state[16]) {
    quarterround(&state[0], &state[1], &state[2], &state[3]);
    quarterround(&state[5], &state[6], &state[7], &state[4]);
    quarterround(&state[10], &state[11], &state[8], &state[9]);
    quarterround(&state[15], &state[12], &state[13], &state[14]);
}


void columnround(uint32_t state[16]) {
    quarterround(&state[0], &state[4], &state[8], &state[12]);
    quarterround(&state[5], &state[9], &state[13], &state[1]);
    quarterround(&state[10], &state[14], &state[2], &state[6]);
    quarterround(&state[15], &state[3], &state[7], &state[11]);
}


void doubleround(uint32_t state[16]) {
    columnround(state);
    rowround(state);
}


uint32_t littleendian(uint32_t word) {
    return ((word >> 24) & 0xff) | ((word >> 8) & 0xff00) | ((word << 8) & 0xff0000) | ((word << 24) & 0xff000000);
}


void salsa20_hash(uint32_t state_in[16], uint32_t state_out[16]) {
    uint32_t state[16];

    for (int i = 0; i < 16; i++) {
        state_in[i] = littleendian(state_in[i]);
        state[i] = state_in[i];
    }

    // 10 double rounds -> 20 rounds
    for (int i = 0; i < 10; i++) {
        doubleround(state);
    }

    for (int i = 0; i < 16; i++) {
        state_out[i] = littleendian(state[i] + state_in[i]);
    }
}


void salsa20_expansion(uint32_t state_in[16], uint32_t state_out[16], uint32_t key[8], uint32_t nonce[4]) {
    // constant = "expand 32-byte k"
    const uint32_t constant[4] = {0x65787061, 0x6E642033, 0x322D6279, 0x7465206B};
    state_in[0] = constant[0];
    state_in[5] = constant[1];
    state_in[10] = constant[2];
    state_in[15] = constant[3];

    // key
    state_in[1] = key[0];
    state_in[2] = key[1];
    state_in[3] = key[2];
    state_in[4] = key[3];
    state_in[11] = key[4];
    state_in[12] = key[5];
    state_in[13] = key[6];
    state_in[14] = key[7];

    // nonce
    state_in[6] = nonce[0];
    state_in[7] = nonce[1];
    state_in[8] = nonce[2]; // position
    state_in[9] = nonce[3]; // position

    salsa20_hash(state_in, state_out);
}


void salsa20_encryption_decryption(uint32_t key[8], uint32_t nonce[2], uint32_t *message_in, uint32_t *message_out, int message_length) {
    uint32_t state_in[16], state_out[16];

    uint32_t nonce_with_position[4];
    nonce_with_position[0] = nonce[0];
    nonce_with_position[1] = nonce[1];

    uint64_t position = 0;
    convert_64_bit_into_two_32_bit(position, &nonce_with_position[3], &nonce_with_position[2]);

    // iterates over the message
    for (int i = 0; i < message_length; i++) {
        // a new state every 16 fields (a state has 16 array fields)
        if (i % 16 == 0) {
            position = update_position(position, nonce_with_position, i);
            salsa20_expansion(state_in, state_out, key, nonce_with_position);
        }
        message_out[i] = message_in[i] ^ state_out[i % 16];
    }
}


uint64_t update_position(uint64_t position, uint32_t nonce_with_position[4], int loop_index) {
    // position is stored in 64-bits and must be converted into two 32-bits in the state/nonce
    position = convert_two_32_bit_into_64_bit(nonce_with_position[3], nonce_with_position[2]);
    position = (loop_index / 16);
    convert_64_bit_into_two_32_bit(position, &nonce_with_position[3], &nonce_with_position[2]);

    nonce_with_position[2] = littleendian(nonce_with_position[2]);
    nonce_with_position[3] = littleendian(nonce_with_position[3]);

    return position;
}


void print_internal_state_of_salsa(uint32_t state[16]) {
    for (int i = 0; i < 16; i++) {
        if (i % 4 == 0) printf("\n");
        printf("0x%08x ", state[i]);
    }

    printf("\n");
}


void plaintext_to_ciphertext_blocks(bignum *ciphertext_blocks, char *plaintext, uint32_t key[8], uint32_t nonce[2]) {
    const int number_of_bignums = calculate_number_of_bignums_from_string(plaintext);

    // string to bignum array
    bignum bignum_array_plaintext[number_of_bignums];
    string_to_bignum_array(bignum_array_plaintext, plaintext);

    // bignum array to one uint32_t array
    const int number_of_chunks = number_of_bignums * 4;
    uint32_t plaintext_hex[number_of_chunks];
    bignum_blocks_to_one_array(plaintext_hex, bignum_array_plaintext, number_of_bignums);

    // encryption
    uint32_t ciphertext_hex[number_of_chunks];
    salsa20_encryption_decryption(key, nonce, plaintext_hex, ciphertext_hex, number_of_chunks);

    uint32_t one_block[4];

    // ciphertext array to an array of bignums which represents the several blocks for MAGIC
    for (int i = 0, k = 0; i < number_of_chunks; i++, k++) {
        one_block[i%4] = ciphertext_hex[i];

        // every 128 bits add the bignum to the array with block[0] until block[3]
        if (k == 3) {
            ciphertext_blocks[((i+1)/4)-1] = init_bignum(one_block);
            k = -1;  // start again at k = 0
        }
    }
}


void ciphertext_blocks_to_plaintext_as_str(unsigned char *plaintext, bignum ciphertext_blocks[], int number_of_blocks, uint32_t key[8], uint32_t nonce[2]) {
    const int number_of_chunks = number_of_blocks * 4;

    // bignum array to one uint32_t array
    uint32_t ciphertext_hex[number_of_chunks];
    bignum_blocks_to_one_array(ciphertext_hex, ciphertext_blocks, number_of_blocks);

    // decryption
    uint32_t plaintext_hex[number_of_chunks];
    salsa20_encryption_decryption(key, nonce, ciphertext_hex, plaintext_hex, number_of_chunks);

    // convert to bignum array and ignore leading zeros
    bignum bignum_array_plaintext[number_of_blocks];
    init_bignum_array(bignum_array_plaintext, number_of_blocks, plaintext_hex, number_of_chunks);

    // convert to string
    bignum_array_to_string(plaintext, bignum_array_plaintext, number_of_blocks);
}
