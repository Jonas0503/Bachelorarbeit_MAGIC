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


bignum string_to_bignum(char *plaintext) {
    int plaintext_size = strlen(plaintext);

    if (plaintext_size == 0) {
        return init_bignum_to_zero();
    }

    int size = ((plaintext_size - 1) / 4) + 1;
    uint32_t *hex = malloc(sizeof(uint32_t) * size);

    for (int i = 0; i < size; i++) {
        hex[i] = 0x0;
    }

    int shifts = 0;
    int k = size-1;

    for (int i = 0; i < plaintext_size; i++) {
        hex[k] = hex[k] | (plaintext[plaintext_size-1-i] << shifts);
        shifts += 8;
        if (shifts >= 32) {
            shifts = 0;
            k--;
        }
    }

    bignum r = init_bignum(hex, size);
    free(hex);

    return r;
}


unsigned char *bignum_to_string(bignum n) {
    int number_of_chars = n.number_of_chunks * BLOCKSIZE;

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

    int shifts = 0;
    int chunk_index = n.number_of_chunks-1;
    for (int i = number_of_chars-1; i >= 0; i--) {
        string[i] = ((n.chunks[chunk_index] >> shifts) & 0xff);
        shifts += 8;

        if (shifts >= 32) {
            shifts = 0;
            chunk_index--;
        }
    }

    string[number_of_chars] = '\0';

    return string;
}


int determine_number_of_ciphertext_blocks(bignum blocks[]) {
    int number_of_blocks;
    for (number_of_blocks = 0; blocks[number_of_blocks].number_of_chunks == 4; number_of_blocks++) {}

    return number_of_blocks;
}


bignum ciphertext_bignum_blocks_to_one_bignum(bignum ciphertext_blocks[]) {
    int number_of_blocks = determine_number_of_ciphertext_blocks(ciphertext_blocks);

    uint32_t *array = malloc(sizeof(uint32_t) * (number_of_blocks * BLOCKSIZE));

    for (int i = 0, k = 0; i < number_of_blocks; i++, k += BLOCKSIZE) {
        memcpy(array + k, ciphertext_blocks[i].chunks, sizeof(uint32_t) * BLOCKSIZE);
    }

    bignum res = init_bignum(array, number_of_blocks * BLOCKSIZE);
    free(array);

    return res;
}
