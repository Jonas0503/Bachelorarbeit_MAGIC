#include "util.h"

#include "stdlib.h"
#include "string.h"
#include "stdio.h"


// defined in magic_mode.c
extern const int BLOCKSIZE;


uint32_t *allocate_memory_for_chunks(bool already_allocated, bignum *n, int size_in_bytes) {
    if (already_allocated) {
        n->chunks = realloc(n->chunks, size_in_bytes);
    }
    else {
        n->chunks = malloc(size_in_bytes);
    }

    return n->chunks;
}


void convert_64_bit_into_two_32_bit(uint64_t a, uint32_t *left_part, uint32_t *right_part) {
    uint32_t left_value = (a & 0xffffffff00000000) >> 32;
    uint32_t right_value = a & 0xffffffff;

    (*left_part) = left_value;
    (*right_part) = right_value;
}


uint64_t convert_two_32_bit_into_64_bit(uint32_t left_part, uint32_t right_part) {
    return (((uint64_t)left_part) << 32) | right_part;
}


bignum string_to_bignum(char *text) {
    int plaintext_size = strlen(text);

    if (plaintext_size == 0) {
        return init_bignum_to_zero();
    }

    // the number of chunks for the created bignum
    int number_of_chunks = ((plaintext_size - 1) / 4) + 1;
    uint32_t *hex = malloc(sizeof(uint32_t) * number_of_chunks);

    // default all chunks to zero
    for (int i = 0; i < number_of_chunks; i++) {
        hex[i] = 0x0;
    }

    // fill up the chunks starting from the back
    int shifts = 0;
    int k = number_of_chunks-1;
    for (int i = 0; i < plaintext_size; i++) {
        // one char equals 8 bit
        hex[k] = hex[k] | (text[plaintext_size-1-i] << shifts);
        shifts += 8;
        // every 32 bit a new chunk
        if (shifts >= 32) {
            shifts = 0;
            k--;
        }
    }

    bignum r = init_bignum(hex, number_of_chunks);
    free(hex);

    return r;
}


unsigned char *bignum_to_string(bignum n) {
    int number_of_chars = n.number_of_chunks * BLOCKSIZE;

    // one char -> two hex digits
    // counts the number of resulting chars without the leading zeros
    for (int i = 0; i < n.number_of_chunks; i++) {
        if ((n.chunks[i] >> 24) != 0) break;
        if ((n.chunks[i] >> 24) == 0) number_of_chars--;
        if (((n.chunks[i] >> 16) & 0xff) != 0) break;;
        if (((n.chunks[i] >> 16) & 0xff) == 0) number_of_chars--;
        if (((n.chunks[i] >> 8) & 0xff) != 0) break;
        if (((n.chunks[i] >> 8) & 0xff) == 0) number_of_chars--;
        if ((n.chunks[i] & 0xff) != 0) break;
        if ((n.chunks[i] & 0xff) == 0) number_of_chars--;
    }

    unsigned char *string = malloc(sizeof(unsigned char) * (number_of_chars + 1));

    // fill up the char array starting from the back until the leading zeros
    int shifts = 0;
    int chunk_index = n.number_of_chunks-1;
    for (int i = number_of_chars-1; i >= 0; i--) {
        string[i] = ((n.chunks[chunk_index] >> shifts) & 0xff);
        shifts += 8;
        // every 32 bits a new chunk
        if (shifts >= 32) {
            shifts = 0;
            chunk_index--;
        }
    }

    string[number_of_chars] = '\0';

    return string;
}


int calculate_number_of_ciphertext_blocks(bignum ciphertext_blocks[]) {
    // counts the blocks until the zero block at the end (see function "plaintext_to_ciphertext_blocks()" in "magic_mode.c")
    // ciphertext blocks are always 128-bit (4 chunks)
    int number_of_blocks;
    for (number_of_blocks = 0; ciphertext_blocks[number_of_blocks].number_of_chunks == 4; number_of_blocks++) {}

    return number_of_blocks;
}


bignum ciphertext_bignum_blocks_to_one_bignum(bignum ciphertext_blocks[]) {
    int number_of_blocks = calculate_number_of_ciphertext_blocks(ciphertext_blocks);
    uint32_t *array = malloc(sizeof(uint32_t) * (number_of_blocks * BLOCKSIZE));

    // every 128-bit a new chunk gets copied into the array of the resulting bignum
    // ciphertext blocks are always 128-bit (4 chunks)
    for (int i = 0, k = 0; i < number_of_blocks; i++, k += BLOCKSIZE) {
        memcpy(array + k, ciphertext_blocks[i].chunks, sizeof(uint32_t) * BLOCKSIZE);
    }

    bignum res = init_bignum(array, number_of_blocks * BLOCKSIZE);
    free(array);

    return res;
}


void pad(bignum *result, bool already_allocated, bignum n) {
    bignum tmp_n = copy_bignum(n);

    int size_new = tmp_n.number_of_chunks + (((tmp_n.number_of_chunks % BLOCKSIZE) - BLOCKSIZE) * -1);
    result->number_of_chunks = size_new;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * size_new);

    // padding per chunk and the padding is always existing
    for (int i = 0; i < size_new; i++) {
        if (i < tmp_n.number_of_chunks) {
            result->chunks[i] = tmp_n.chunks[i];
        }
        else {
            result->chunks[i] = size_new - tmp_n.number_of_chunks;
        }
    }

    destroy_bignum(tmp_n);
}


void unpad(bignum *result, bool already_allocated, bignum n) {
    bignum tmp_n = copy_bignum(n);

    // determine number of chunks without the padding
    uint32_t value_in_last_chunk = tmp_n.chunks[tmp_n.number_of_chunks-1];
    int number_of_chunks = tmp_n.number_of_chunks - value_in_last_chunk;
    result->number_of_chunks = number_of_chunks;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * number_of_chunks);

    // copy the values until the padding
    for (int i = 0; i < number_of_chunks; i++) {
        result->chunks[i] = tmp_n.chunks[i];
    }

    destroy_bignum(tmp_n);
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
        shift_right_by_one_bignum(&tmp_n, true, tmp_n);
    }

    destroy_bignum(tmp_n);

    return number_of_ones;
}


void destroy_bignum_array(bignum ciphertext_blocks[], int number_of_blocks) {
    for (int i = 0; i < number_of_blocks; i++) {
        destroy_bignum(ciphertext_blocks[i]);
    }
    free(ciphertext_blocks);
}


bignum polynom_to_bignum(int bit_indices[], int size) {
    // TODO: !!! Als Binärstring speichern; Diesen String an jedem vierten char splitten und dann daraus jeweils uint32_t Werte bilden
    // https://stackoverflow.com/questions/11493609/how-to-split-a-string-every-4-chars-and-then-memorize-the-fragments
    // TODO: Mit bignums einfach rechnen, wie ich es in Python gemacht habe

    /* bignum n = init_bignum_to_zero();

    for (int i = 0; i < size; i++) {
        if (bit_indices[i] == 0)
    } */
}


void generate_error_vectors(int threshold) {
    int possible_indices_with_one[128];
    for (int i = 0; i < 128; i++) {
        possible_indices_with_one[i] = i;
    }

    // TODO: polynom to bignum
}
