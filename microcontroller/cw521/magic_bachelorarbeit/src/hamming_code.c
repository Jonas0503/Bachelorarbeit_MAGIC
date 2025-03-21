#include "hamming_code.h"
#include "util_functions.h"

#include "string.h"
#include "stdio.h"
#include "math.h"


int number_of_encrypted_ciphertext_blocks_with_parity_from_string(char *text) {
    int plaintext_size = strlen(text);

    // number of bignums without parity
    int number_of_filled_chunks = (((plaintext_size - 1) / BLOCKSIZE) + 1);
    int number_of_ciphertext_blocks = (number_of_filled_chunks + (BLOCKSIZE-1)) / BLOCKSIZE;

    // number of bignums to add when parity is used in each block
    int parity_bits_to_add = 8 * number_of_ciphertext_blocks;
    int ciphertext_blocks_to_add;
    if (parity_bits_to_add % 128 == 0) {
        ciphertext_blocks_to_add = (parity_bits_to_add / 128);
    }
    else {
        ciphertext_blocks_to_add = (parity_bits_to_add / 128) + 1;
    }

    // determine number_of_blocks with added blocks for parity
    int parity_bits_added_blocks = 8 * ciphertext_blocks_to_add;
    if ((parity_bits_added_blocks + parity_bits_to_add) % 128 == 0) {
        ciphertext_blocks_to_add = ((parity_bits_added_blocks + parity_bits_to_add) / 128);
    }
    else {
        ciphertext_blocks_to_add = ((parity_bits_added_blocks + parity_bits_to_add) / 128) + 1;
    }

    // number of bignums with parity
    return number_of_ciphertext_blocks + ciphertext_blocks_to_add;
}


void bignums_to_bit_arrays_with_space_for_parity_bits(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity) {
    // all fields should be zero at the start
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays[i][k] = false;
        }
    }

    // makes everything easier
    bool bit_arrays_no_parity[number_of_bignums][128];
    bignum_array_to_bit_arrays(bit_arrays_no_parity, bignum_blocks, number_of_bignums);

    volatile int index_bit_arrays_parity = number_of_bignums_with_parity-1;
    int bit_index_parity_array = 127;

    // iterate over all bit arrays starting from the back
    for (int i = number_of_bignums-1; i >= 0; i--) {
        // iterate over all bits
        for (int k = 127; k >= 0; k--) {
            // checks if bit index is used for parity and if true skip this position
            if ((bit_index_parity_array & (bit_index_parity_array-1)) == 0) {
                k++;
            }
            else {
                bit_arrays[index_bit_arrays_parity][bit_index_parity_array] = bit_arrays_no_parity[i][k];
            }

            bit_index_parity_array--;

            // bit array with parity bits is full -> go to the next one
            if (bit_index_parity_array == -1) {
                index_bit_arrays_parity--;
                bit_index_parity_array = 127;
            }
        }
    }
}


void set_parity_bits(bool bit_arrays[][128], int number_of_bignums_with_parity) {
    int result_xor_all_set_bits = 0;
    int number_of_set_bits = 0;

    // iterate over all bits starting from the last (least significant) bit
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            // XOR all set bits in one bignum/block together and count them
            if (bit_arrays[i][k]) {
                result_xor_all_set_bits ^= k;
                number_of_set_bits++;
            }
        }

        // iterate over the bits from the result of the XOR
        for (int k = 0; k < 7; k++) {
            // a one indicates the position for a change in the parity bits
            if ((result_xor_all_set_bits >> k) & 1) {
                int index_parity_bit = (int)pow(2, k);
                bit_arrays[i][index_parity_bit] = !(bit_arrays[i][index_parity_bit]);

                if (bit_arrays[i][index_parity_bit]) {
                    number_of_set_bits++;
                }
            }
        }

        // set the first bit to detect two bit errors
        if (number_of_set_bits % 2 == 1) {
            bit_arrays[i][0] = true;
        }

        // starting with a new bignum/block
        result_xor_all_set_bits = 0;
        number_of_set_bits = 0;
    }
}


void bit_arrays_to_bignum_array(bignum *bignum_array, int number_of_bignums, bool bit_arrays[][128]) {
    // iterate over all blocks
    for (int i = 0; i < number_of_bignums; i++) {
        bignum_array[i] = init_bignum_to_zero();
        // iterate over the chunks in the bignum
        for (int k = 0; k < 4; k++) {
            // iterate over the bits in the chunk -> one chunk = 32-bits
            for (int bit_index = 0; bit_index < 32; bit_index++) {
                // "put" the bits in the chunk
                bignum_array[i].chunks[k] <<= 1;
                if (bit_arrays[i][bit_index+(k*32)]) {
                    bignum_array[i].chunks[k] ^= 1;
                }
            }
        }
    }
}


void add_parity_to_bignum_array(bignum *bignums_with_parity, bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity) {
    // contains the bit representation of bignum_blocks with space for the parity bits
    bool bit_arrays[number_of_bignums_with_parity][128];

    bignums_to_bit_arrays_with_space_for_parity_bits(bit_arrays, bignum_blocks, number_of_bignums, number_of_bignums_with_parity);
    set_parity_bits(bit_arrays, number_of_bignums_with_parity);
    bit_arrays_to_bignum_array(bignums_with_parity, number_of_bignums_with_parity, bit_arrays);
}


void bignum_array_to_bit_arrays(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums) {
    // set all to zero
    for (int i = 0; i < number_of_bignums; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays[i][k] = false;
        }
    }

    int bit_index = 127;

    // iterate over all bignums
    for (int i = number_of_bignums-1; i >= 0; i--) {
        // iterate over all chunks
        for (int k = 3; k >= 0; k--) {
            // iterate over all bits and adds them to the chunk
            for (int j = 0; j < 32; j++) {
                bool bit = (bignum_blocks[i].chunks[k] >> j) & 1;
                bit_arrays[i][bit_index] = bit;
                bit_index--;
            }
        }
        // starting with a new bit array
        bit_index = 127;
    }
}


hc_result verify_hamming_code(bignum *ciphertext_blocks, int number_of_bignums) {
    hc_result result;

    bool bit_arrays[number_of_bignums][128];
    bignum_array_to_bit_arrays(bit_arrays, ciphertext_blocks, number_of_bignums);

    int result_xor_all_set_bits = 0;
    int number_of_set_bits = 0;
    bool correction_took_place = false;

    // iterate over all bignums/blocks
    for (int i = 0; i < number_of_bignums; i++) {
        // iterate over all bits
        for (int k = 0; k < 128; k++) {
            // XOR all set bits in one bignum/block together and count them
            if (bit_arrays[i][k]) {
                result_xor_all_set_bits ^= k;
                number_of_set_bits++;
            }
        }

        // two bit error was detected
        if ((result_xor_all_set_bits != 0) && ((number_of_set_bits % 2) == 0)) {
            bignum bignum_array_zero[1];
            bignum zero = init_bignum_to_zero();
            bignum_array_zero[0] = zero;

            result.correction_successful = false;
            result.one_bit_error = false;
            result.two_bit_error = true;
            result.ciphertext_blocks_with_parity = bignum_array_zero;
            result.tag_with_parity = init_bignum_to_zero();

            return result;
        }

        // one bit error in a bignum/block gets corrected
        if ((result_xor_all_set_bits != 0) && ((number_of_set_bits % 2) == 1)) {
            bit_arrays[i][result_xor_all_set_bits] = !(bit_arrays[i][result_xor_all_set_bits]);
            correction_took_place = true;
        }

        result_xor_all_set_bits = 0;
        number_of_set_bits = 0;
    }

    // convert the corrected blocks
    bit_arrays_to_bignum_array(ciphertext_blocks, number_of_bignums, bit_arrays);

    // one bit error
    if (correction_took_place) {
        result.correction_successful = true;
        result.one_bit_error = true;
        result.two_bit_error = false;
        result.ciphertext_blocks_with_parity = ciphertext_blocks;
        result.tag_with_parity = init_bignum_to_zero();

        return result;
    }

    // no error -> result_xor_all_set_bits is zero in each block
    bignum bignum_array_zero[1];
    bignum zero = init_bignum_to_zero();
    bignum_array_zero[0] = zero;

    result.correction_successful =  true;
    result.one_bit_error = false;
    result.two_bit_error = false;
    result.ciphertext_blocks_with_parity = bignum_array_zero;
    result.tag_with_parity = init_bignum_to_zero();

    return result;
}


void remove_parity_from_encrypted_ciphertext_blocks(bignum *blocks_no_parity, bignum *ciphertext_blocks_with_parity, int number_of_blocks_with_parity, int number_of_blocks) {
    bool bit_arrays_parity[number_of_blocks_with_parity][128];
    bignum_array_to_bit_arrays(bit_arrays_parity, ciphertext_blocks_with_parity, number_of_blocks_with_parity);

    bool bit_arrays_no_parity[number_of_blocks][128];
    for (int i = 0; i < number_of_blocks; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays_no_parity[i][k] = false;
        }
    }

    // converts the bit arrays with parity to bit arrays with no parity
    int counter_no_parity_blocks = 127;
    int array_index = number_of_blocks-1;
    // iterate over all blocks
    for (int i = number_of_blocks_with_parity-1; i >= 0; i--) {
        // iterate over all bits
        for (int k = 127; k >= 0; k--) {
            // skip bit if the index is a power of two
            if ((k & (k - 1)) == 0) {
                continue;
            }

            // add bit to the array with no parity values and decrement the counter
            bit_arrays_no_parity[array_index][counter_no_parity_blocks] = bit_arrays_parity[i][k];
            counter_no_parity_blocks--;

            // start with a new block for bit_arrays_no_parity if all indices are filled
            if (counter_no_parity_blocks == -1) {
                counter_no_parity_blocks = 127;
                array_index--;
            }
        }
    }

    bit_arrays_to_bignum_array(blocks_no_parity, number_of_blocks, bit_arrays_no_parity);
}


void print_bit_arrays(bool bit_arrays[][128], int number_of_blocks) {
    for (int i = 0; i < number_of_blocks; i++) {
        printf("0b");
        for (int k = 0; k < 128; k++) {
            printf("%i", bit_arrays[i][k]);
        }
        printf("\n");
    }
}
