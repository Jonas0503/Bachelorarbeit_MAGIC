#include "hamming_code.h"
#include "util.h"

#include "string.h"
#include "stdio.h"
#include "math.h"


int calculate_number_of_bignums_with_parity_from_string(char *text) {
    int plaintext_size = strlen(text);

    int number_of_filled_chunks = (((plaintext_size - 1) / BLOCKSIZE) + 1);
    int number_of_bignums = (number_of_filled_chunks + (BLOCKSIZE-1)) / BLOCKSIZE;

    int parity_bits_to_add = 8 * number_of_bignums;
    int bignums_to_add = (parity_bits_to_add / 129) + 1;

    return number_of_bignums + bignums_to_add;
}


void bignum_array_to_bit_arrays_with_space_for_parity_bits(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity) {
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays[i][k] = false;
        }
    }

    int number_of_chunks = number_of_bignums * BLOCKSIZE;
    int bit_index = 127;
    int array_index_bits = number_of_bignums_with_parity - 1;
    int array_index_bignum_array = number_of_bignums - 1;
    bool next_block = false;

    for (int i = number_of_chunks-1; i >= 0; i--) {
        for(int k = 0; k < 32; k++) {
            if (bit_index == 2) {
                bit_index = 127;
                for(; k < 32; k++) {
                    bool bit = (bignum_blocks[array_index_bignum_array].chunks[i % 4] >> k) & 1;
                    bit_arrays[array_index_bits-1][bit_index] = bit;
                    bit_index--;
                }

                next_block = true;
                break;
            }
            if ((bit_index & (bit_index-1)) == 0) {
                bit_index--;
            }
            bool bit = (bignum_blocks[array_index_bignum_array].chunks[i % 4] >> k) & 1;
            bit_arrays[array_index_bits][bit_index] = bit;
            bit_index--;
        }

        if (next_block) {
            next_block = false;
            array_index_bits--;
            array_index_bignum_array--;
        }
    }
}


void set_parity_bits(bool bit_arrays[][128], int number_of_bignums_with_parity) {
    int value = 0;
    int number_of_set_bits = 0;

    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            if (bit_arrays[i][k]) {
                value ^= k;
                number_of_set_bits++;
            }
        }

        for (int k = 0; k < 7; k++) {
            if ((value >> k) & 1) {
                int index_parity_bit = (int)pow(2, k);
                bit_arrays[i][index_parity_bit] = !(bit_arrays[i][index_parity_bit]);

                if (bit_arrays[i][index_parity_bit]) {
                    number_of_set_bits++;
                }
            }
        }

        if (number_of_set_bits % 2 == 1) {
            bit_arrays[i][0] = true;
        }

        value = 0;
        number_of_set_bits = 0;
    }
}


void bit_arrays_to_bignum_array(bignum *bignums_with_parity, int number_of_bignums_with_parity, bool bit_arrays[][128]) {
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        bignums_with_parity[i] = init_bignum_to_zero();
        for (int k = 0; k < 4; k++) {
            for (int bit_index = 0; bit_index < 32; bit_index++) {
                bignums_with_parity[i].chunks[k] <<= 1;
                if (bit_arrays[i][bit_index+(k*32)]) {
                    bignums_with_parity[i].chunks[k] ^= 1;
                }
            }
        }
    }
}


void add_parity_to_bignum_array(bignum *bignums_with_parity, bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity) {
    bool bit_arrays[number_of_bignums_with_parity][128];

    bignum_array_to_bit_arrays_with_space_for_parity_bits(bit_arrays, bignum_blocks, number_of_bignums, number_of_bignums_with_parity);
    set_parity_bits(bit_arrays, number_of_bignums_with_parity);
    bit_arrays_to_bignum_array(bignums_with_parity, number_of_bignums_with_parity, bit_arrays);
}


void bignum_array_to_bit_arrays(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums_with_parity) {
    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            bit_arrays[i][k] = false;
        }
    }

    int bit_index = 127;

    for (int i = number_of_bignums_with_parity-1; i >= 0; i--) {
        for (int k = 3; k >= 0; k--) {
            for (int j = 0; j < 32; j++) {
                bool bit = (bignum_blocks[i].chunks[k] >> j) & 1;
                bit_arrays[i][bit_index] = bit;
                bit_index--;
            }
        }
        bit_index = 127;
    }
}


verify_result verify_hamming_code(bignum *ciphertext_blocks, int number_of_bignums_with_parity, bignum tag) {
    verify_result result;

    bool bit_arrays[number_of_bignums_with_parity][128];
    bignum_array_to_bit_arrays(bit_arrays, ciphertext_blocks, number_of_bignums_with_parity);

    int value = 0;
    int number_of_set_bits = 0;
    bool correction_took_place = false;

    for (int i = 0; i < number_of_bignums_with_parity; i++) {
        for (int k = 0; k < 128; k++) {
            if (bit_arrays[i][k]) {
                value ^= k;
                number_of_set_bits++;
            }
        }

        if ((value != 0) && ((number_of_set_bits % 2) == 0)) {
            bignum bignum_array[1];
            bignum zero = init_bignum_to_zero();
            bignum_array[0] = zero;

            result.correction_successful = false;
            result.ciphertext_blocks = bignum_array;
            result.tag = init_bignum_to_zero();

            return result;
        }

        if ((value != 0) && ((number_of_set_bits % 2) == 1)) {
            bit_arrays[i][value] = !(bit_arrays[i][value]);
            correction_took_place = true;
        }

        value = 0;
        number_of_set_bits = 0;
    }

    bit_arrays_to_bignum_array(ciphertext_blocks, number_of_bignums_with_parity, bit_arrays);

    if (correction_took_place) {
        result.correction_successful = true;
        result.ciphertext_blocks = ciphertext_blocks;
        result.tag = tag;

        return result;
    }

    bignum bignum_array[1];
    bignum zero = init_bignum_to_zero();
    bignum_array[0] = zero;

    result.correction_successful =  true;
    result.ciphertext_blocks = bignum_array;
    result.tag = init_bignum_to_zero();

    return result;
}

// TODO: ciphertext Blöcke mit Parität wieder zurückverwandeln ohne Parität; kommentieren; Testen; Parität auf den kompletten Array (vielleicht, wenn noch Zeit, ansonsten in der Arbeit erklären)
