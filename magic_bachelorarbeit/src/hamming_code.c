#include "hamming_code.h"
#include "util.h"

#include "string.h"
#include "stdio.h"
#include "math.h"


int calculate_number_of_bignums_with_parity_from_string(char *text) {
    int plaintext_size = strlen(text);

    // number of bignums without parity
    int number_of_filled_chunks = (((plaintext_size - 1) / BLOCKSIZE) + 1);
    int number_of_bignums = (number_of_filled_chunks + (BLOCKSIZE-1)) / BLOCKSIZE;

    // number of bignums to add when parity is used in each block
    int parity_bits_to_add = 8 * number_of_bignums;
    int bignums_to_add = (parity_bits_to_add / 129) + 1;

    // number of bignums with parity
    return number_of_bignums + bignums_to_add;
}


void bignum_array_to_bit_arrays_with_space_for_parity_bits(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity) {
    // all fields should be zero at the start
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays[i][k] = false;
        }
    }

    int number_of_chunks = number_of_bignums * 4;
    int bit_index = 127;
    int array_index_bits = number_of_bignums_with_parity - 1;
    int array_index_bignum_array = number_of_bignums - 1;
    bool next_block = false;

    // iterate over all bignum chunks in the bignum_blocks array
    // starting with the last chunk
    for (int i = number_of_chunks-1; i >= 0; i--) {
        // iterate over all bits of one chunk
        for(int k = 0; k < 32; k++) {
            // parity bits at positions 0, 1 and 2 (positions with power of 2)
            if (bit_index == 2) {
                // the rest of the current chunk gets to a new bit array and skip position 0, 1 and 2
                bit_index = 127;
                for(; k < 32; k++) {
                    bool bit = (bignum_blocks[array_index_bignum_array].chunks[i % 4] >> k) & 1;
                    bit_arrays[array_index_bits-1][bit_index] = bit;
                    bit_index--;
                }

                // continue with next chunk
                next_block = true;
                break;
            }
            // parity bits at positions with power of 2 -> skip this index for a parity bit
            if ((bit_index & (bit_index-1)) == 0) {
                bit_index--;
            }

            // set bits in the bit array
            bool bit = (bignum_blocks[array_index_bignum_array].chunks[i % 4] >> k) & 1;
            bit_arrays[array_index_bits][bit_index] = bit;
            bit_index--;
        }

        // go to the "previous" bit array
        if (next_block) {
            next_block = false;
            array_index_bits--;
        }
        // go to the "previous" bignum if all chunks were iterated
        if (i % 4 == 0) {
            array_index_bignum_array--;
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

    bignum_array_to_bit_arrays_with_space_for_parity_bits(bit_arrays, bignum_blocks, number_of_bignums, number_of_bignums_with_parity);
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
            bignum bignum_array[1];
            bignum zero = init_bignum_to_zero();
            bignum_array[0] = zero;

            result.correction_successful = false;
            result.one_bit_error = false;
            result.two_bit_error = true;
            result.ciphertext_blocks_with_parity = bignum_array;
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
    bignum bignum_array[1];
    bignum zero = init_bignum_to_zero();
    bignum_array[0] = zero;

    result.correction_successful =  true;
    result.one_bit_error = false;
    result.two_bit_error = false;
    result.ciphertext_blocks_with_parity = bignum_array;
    result.tag_with_parity = init_bignum_to_zero();

    return result;
}


void remove_parity_from_ciphertext_blocks(bignum *blocks_no_parity, bignum *ciphertext_blocks_with_parity, int number_of_blocks_with_parity, int number_of_blocks) {
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
