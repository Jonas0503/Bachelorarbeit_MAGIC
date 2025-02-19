#include "bignum.h"
#include "util.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdbool.h"
#include "string.h"


bignum init_bignum(uint32_t *hex, int size) {
    bignum n;
    n.number_of_chunks = size;
    n.chunks = malloc(size * sizeof(uint32_t));

    // most significant bytes (MSB) are in chunks[0] and least significant bytes (LSB) are in chunks[size-1]
    for (int i = 0; i < size; i++) {
        n.chunks[i] = hex[i];
    }

    return n;
}


bignum init_bignum_to_zero() {
    bignum n;

    n.number_of_chunks = 1;
    n.chunks = malloc(sizeof(uint32_t));
    n.chunks[0] = 0x0;

    return n;
}


void set_existing_bignum_to_zero(bignum *n) {
    n->number_of_chunks = 1;
    n->chunks = realloc(n->chunks, sizeof(uint32_t));
    n->chunks[0] = 0x0;
}


bignum init_bignum_to_one() {
    bignum n;

    n.number_of_chunks = 1;
    n.chunks = malloc(sizeof(uint32_t));
    n.chunks[0] = 0x1;

    return n;
}


void set_existing_bignum_to_one(bignum *n) {
    n->number_of_chunks = 1;
    n->chunks = realloc(n->chunks, sizeof(uint32_t));
    n->chunks[0] = 0x1;
}


void destroy_bignum(bignum n) {
    free(n.chunks);
}


void print_bignum(bignum n) {
    bool chunk_before_is_zero = false;
    int size = n.number_of_chunks;

    printf("0x");

    if (n.number_of_chunks == 0) printf("0");

    // Starting with the most significant chunk at the beginning of the array and ignore all leading zeros
    for (int i = 0; i < size; i++) {
        if (i == 0 && n.chunks[i] == 0){
            chunk_before_is_zero = true;
            continue;
        }
        else if (chunk_before_is_zero && i == size-1) {
            printf("0");
        }
        else if (chunk_before_is_zero && n.chunks[i] == 0) {
            continue;
        }
        else if (i == 0) {
            chunk_before_is_zero = false;
            printf("%x", n.chunks[i]);
        }
        else {
            chunk_before_is_zero = false;
            printf("%08x", n.chunks[i]);
        }
    }

    printf("\n");
}


void xor_bignum(bignum *result, bool already_allocated, bignum a, bignum b) {
    // Copies the bignums because wrong results occur when the parameters result, a, b are all the same input variable (all pointing to same memory?!)
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);
    int size_a = tmp_a.number_of_chunks;
    int size_b = tmp_b.number_of_chunks;

    int resulting_size = size_a;
    if (size_a < size_b) resulting_size = size_b;

    result->number_of_chunks = resulting_size;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * resulting_size);

    // One XOR per chunk starting at the LSB on the right for each number
    for (int k = 0, i_a = size_a-1, i_b = size_b-1; i_a >= 0 || i_b >= 0; i_a--, i_b--, k++) {
        if (k >= size_a) {
            result->chunks[resulting_size-1-k] = tmp_b.chunks[i_b];
        }
        else if (k >= size_b) {
            result->chunks[resulting_size-1-k] = tmp_a.chunks[i_a];
        }
        else {
            result->chunks[resulting_size-1-k] = tmp_a.chunks[i_a] ^ tmp_b.chunks[i_b];
        }
    }

    destroy_bignum(tmp_a);
    destroy_bignum(tmp_b);
}


bool is_bignum_not_zero(bignum n) {
    if (n.number_of_chunks == 0) return false;

    for (int i = 0; i < n.number_of_chunks; i++) {
        if (n.chunks[i] != 0x0) return true;
    }

    return false;
}


void shift_left_by_one_bignum(bignum *result, bool already_allocated, bignum n) {
    // Copies the bignums because wrong results occur when the parameters result and n are the same input variable (all pointing to same memory?!)
    bignum tmp_n = copy_bignum(n);

    // Checks if the most significant bit is a 1 or 0. When its a 1 one more chunk is needed.
    if (n.chunks[0] & (1 << 31)) {
        result->number_of_chunks = tmp_n.number_of_chunks + 1;

        uint32_t *hex = malloc(sizeof(uint32_t) * result->number_of_chunks);

        // A 0x0 chunk gets added at the beginning; otherwise the sizes of the two numbers differ (problems in for-loop for the actual shifting)
        for (int i = 0; i < result->number_of_chunks; i++) {
            if (i == 0) {
                hex[i] = 0x0;
            }
            else {
                hex[i] = tmp_n.chunks[i-1];
            }
        }

        destroy_bignum(tmp_n);
        tmp_n = init_bignum(hex, result->number_of_chunks);
        free(hex);
    }
    else {
        result->number_of_chunks = tmp_n.number_of_chunks;
    }

    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * result->number_of_chunks);

    // Left shift per chunk
    for (int i = 0; i < result->number_of_chunks; i++) {
        if (i == result->number_of_chunks-1) {
            result->chunks[i] = tmp_n.chunks[i] << 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block before is shifted left to the current block
            result->chunks[i] = (tmp_n.chunks[i] << 1) | (tmp_n.chunks[i+1] >> 31);
        }
    }

    destroy_bignum(tmp_n);
}


void shift_right_by_one_bignum(bignum *result, bool already_allocated, bignum n) {
    // Copies the bignums because wrong results occur when the parameters result and n are the same input variable (all pointing to same memory?!)
    bignum tmp_n = copy_bignum(n);

    result->number_of_chunks = tmp_n.number_of_chunks;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * tmp_n.number_of_chunks);

    // Right shift per chunk
    for (int i = 0; i < tmp_n.number_of_chunks; i++) {
        if (i == 0) {
            result->chunks[i] = tmp_n.chunks[i] >> 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block after is shifted right to the current block
            result->chunks[i] = (tmp_n.chunks[i] >> 1) | (tmp_n.chunks[i-1] << 31);
        }
    }

    destroy_bignum(tmp_n);
}


void shift_right_by_x_bignum(bignum *result, bool already_allocated, bignum n, int x) {
    // Copies the bignums because wrong results occur when the parameters result and n are the same input variable (all pointing to same memory?!)
    bignum tmp_n = copy_bignum(n);

    for (int i = 0; i < x; i++) {
        shift_right_by_one_bignum(result, already_allocated, tmp_n);
        tmp_n.number_of_chunks = result->number_of_chunks;
        memcpy(tmp_n.chunks, result->chunks, sizeof(uint32_t) * n.number_of_chunks);
        already_allocated = true;
    }

    destroy_bignum(tmp_n);
}


bool is_bignum_odd(bignum n) {
    return n.chunks[n.number_of_chunks-1] & 0x1;
}


bool is_bignum_inside_galois_field(bignum n, int degree) {
    bignum x;

    // If the (degree)th bit is set the number is outside the Galois Field
    shift_right_by_x_bignum(&x, false, n, degree);
    bool result =  !is_bignum_not_zero(x);
    destroy_bignum(x);

    return result;
}


bignum copy_bignum(bignum n) {
    bignum tmp_n;
    tmp_n.number_of_chunks = n.number_of_chunks;
    tmp_n.chunks = malloc(sizeof(uint32_t) * n.number_of_chunks);
    memcpy(tmp_n.chunks, n.chunks, sizeof(uint32_t) * n.number_of_chunks);

    return tmp_n;
}


void remove_chunks_with_leading_zeros(bignum *result, bool already_allocated, bignum n) {
    // Copies the bignums because wrong results occur when the parameters result and n are the same input variable (all pointing to same memory?!)
    bignum tmp_n = copy_bignum(n);

    int number_of_chunks_no_leading_zero_chunks = tmp_n.number_of_chunks;

    // counts the chunks until a chunk in the front does not equal zero
    for (int i = 0; i < tmp_n.number_of_chunks; i++) {
        if (tmp_n.chunks[i] != 0x0) {
            break;
        }
        else if (i == tmp_n.number_of_chunks-1) {
            // if the bignum is zero
            break;
        }
        else {
            number_of_chunks_no_leading_zero_chunks--;
        }
    }

    result->number_of_chunks = number_of_chunks_no_leading_zero_chunks;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * result->number_of_chunks);

    for (int i = number_of_chunks_no_leading_zero_chunks-1, k = 0; i >= 0; i--, k++) {
        result->chunks[i] = tmp_n.chunks[n.number_of_chunks-1-k];
    }

    destroy_bignum(tmp_n);
}


bool are_bignums_equal(bignum a, bignum b) {
    if (a.number_of_chunks != b.number_of_chunks) {
        return false;
    }

    for (int i = 0; i < a.number_of_chunks; i++) {
        if (a.chunks[i] != b.chunks[i]) {
            return false;
        }
    }

    return true;
}
