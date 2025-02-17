#include "util.h"

#include "stdlib.h"
#include "string.h"
#include "stdio.h"


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


unsigned char *bignum_blocks_to_string(bignum blocks[]) {
    int number_of_blocks;
    for (number_of_blocks = 0; blocks[number_of_blocks].number_of_chunks == 4; number_of_blocks++) {}

    int number_of_chars = 0;
    for (int i = 0; i < number_of_blocks; i++) {
        for (int k = 0; k < blocks[k].number_of_chunks-1; k++) {
            number_of_chars += 4;
        }
    }

    unsigned char *string = malloc(sizeof(char) * number_of_chars + 1);

    int pos = 0;
    for (int i = 0; i < number_of_blocks; i++) {
        for (int k = 0; k < blocks[i].number_of_chunks; k++) {
            string[pos] = blocks[i].chunks[k] >> 24;
            printf("%x ", string[pos]);
            pos++;
            string[pos] = (blocks[i].chunks[k] >> 16) & 0xff;
            printf("%x ", string[pos]);
            pos++;
            string[pos] = (blocks[i].chunks[k] >> 8) & 0xff;
            printf("%x ", string[pos]);
            pos++;
            string[pos] = blocks[i].chunks[k] & 0xff;
            printf("%x ", string[pos]);
            pos++;
        }
    }

    string[number_of_chars] = '\0';

    return string;
}
