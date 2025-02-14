#include "util.h"

#include "string.h"
#include "stdio.h"
#include "stdlib.h"


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
