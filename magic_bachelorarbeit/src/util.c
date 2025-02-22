#include "util.h"

#include "stdlib.h"
#include "string.h"
#include "stdio.h"


// defined in magic_mode.c
extern const int BLOCKSIZE;


void convert_64_bit_into_two_32_bit(uint64_t a, uint32_t *left_part, uint32_t *right_part) {
    uint32_t left_value = (a & 0xffffffff00000000) >> 32;
    uint32_t right_value = a & 0xffffffff;

    (*left_part) = left_value;
    (*right_part) = right_value;
}


uint64_t convert_two_32_bit_into_64_bit(uint32_t left_part, uint32_t right_part) {
    return (((uint64_t)left_part) << 32) | right_part;
}


const int calculate_number_of_bignums_from_string(const char *text) {
    const int plaintext_size = strlen(text);
    const int number_of_filled_chunks = ((plaintext_size - 1) / BLOCKSIZE) + 1;
    const int number_of_bignums = (number_of_filled_chunks + (BLOCKSIZE-1)) / BLOCKSIZE;

    return number_of_bignums;
}


void string_to_bignum_array(bignum *array_of_bignums, const char *text) {
    const int plaintext_size = strlen(text);
    const int number_of_bignums = calculate_number_of_bignums_from_string(text);

    // leading zeros and easier calculations
    for (int i = 0; i < number_of_bignums; i++) {
        array_of_bignums[i] = init_bignum_to_zero();
    }

    // fill up the chunks starting from the back
    int shifts = 0;
    int k = 3;
    int bignum_array_index = number_of_bignums-1;
    int counter = 0;
    for (int i = 0; i < plaintext_size; i++) {
        // one char equals 8 bit
        array_of_bignums[bignum_array_index].chunks[k] = array_of_bignums[bignum_array_index].chunks[k] | (text[plaintext_size-1-i] << shifts);
        shifts += 8;
        // every 32 bit a new chunk
        if (shifts >= 32) {
            shifts = 0;
            k--;
            counter++;
        }
        // every 4 chunks a new bignum
        if (counter == 4) {
            bignum_array_index--;
            k = 3;
            counter = 0;
        }
    }
}


const int calculate_number_of_chars_from_bignum_array(bignum *array_of_bignums, int array_size) {
    int number_of_chunks = array_size * BLOCKSIZE;
    int number_of_chars = number_of_chunks * 4;

    // one char -> two hex digits
    // counts the number of resulting chars without the leading zeros
    for (int k = 0; k < array_size; k++) {
        for (int i = 0; i < number_of_chunks; i++) {
            if ((array_of_bignums[k].chunks[i] >> 24) != 0) break;
            if ((array_of_bignums[k].chunks[i] >> 24) == 0) number_of_chars--;
            if (((array_of_bignums[k].chunks[i] >> 16) & 0xff) != 0) break;;
            if (((array_of_bignums[k].chunks[i] >> 16) & 0xff) == 0) number_of_chars--;
            if (((array_of_bignums[k].chunks[i] >> 8) & 0xff) != 0) break;
            if (((array_of_bignums[k].chunks[i] >> 8) & 0xff) == 0) number_of_chars--;
            if ((array_of_bignums[k].chunks[i] & 0xff) != 0) break;
            if ((array_of_bignums[k].chunks[i] & 0xff) == 0) number_of_chars--;
        }
    }

    return number_of_chars + 1;
}


void bignum_array_to_string(unsigned char *string, bignum *array_of_bignums, const int array_size) {
    int shifts = 0;
    int chunk_index = 3;
    int counter = 0;
    int bignum_array_index = array_size-1;
    int number_of_chars = calculate_number_of_chars_from_bignum_array(array_of_bignums, array_size);

    // starting at the back of the string because of the leading zeros
    for (int i = number_of_chars-2; i >= 0; i--) {
        string[i] = ((array_of_bignums[bignum_array_index].chunks[chunk_index] >> shifts) & 0xff);
        shifts += 8;
        // every 32 bits a new chunk
        if (shifts >= 32) {
            shifts = 0;
            chunk_index--;
            counter++;
        }
        // every 4 chunks a new bignum
        if (counter == 4) {
            bignum_array_index--;
            counter = 0;
            chunk_index = 3;
        }
    }

    string[number_of_chars-1] = '\0';
}


void ciphertext_bignum_blocks_to_one_array(uint32_t *array, bignum *ciphertext_blocks, const int number_of_blocks) {
    // every 128-bit a new chunk gets copied into the array of the resulting bignum
    // ciphertext blocks are always 128-bit (4 chunks)
    for (int i = 0, k = 0; i < number_of_blocks; i++, k += BLOCKSIZE) {
        memcpy(array + k, ciphertext_blocks[i].chunks, sizeof(uint32_t) * BLOCKSIZE);
    }
}


int hamming_weight(bignum n) {
    bignum tmp_n = copy_bignum(n);
    int number_of_ones = 0;

    // looks always at the last bit and increment the counter if its a one
    while (is_bignum_not_zero(tmp_n)) {
        // if a one is the last bit
        if (is_bignum_odd(tmp_n)) {
            number_of_ones++;
        }

        // look at the next bit
        tmp_n = shift_right_by_one_bignum(tmp_n);
    }

    return number_of_ones;
}


/* bignum polynom_to_bignum(int bit_indices[], int size) {
    // TODO: !!! Als Binärstring speichern; Diesen String an jedem vierten char splitten und dann daraus jeweils uint32_t Werte bilden
    // https://stackoverflow.com/questions/11493609/how-to-split-a-string-every-4-chars-and-then-memorize-the-fragments
    // TODO: Mit bignums einfach rechnen, wie ich es in Python gemacht habe
}


void generate_error_vectors(int threshold) {
    int possible_indices_with_one[128];
    for (int i = 0; i < 128; i++) {
        possible_indices_with_one[i] = i;
    }

    // TODO: polynom to bignum
} */
