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

    // least significant bytes are in chunks[0] and most significant bytes are in chunks[size-1]
    for (int i = 0; i < size; i++) {
        n.chunks[i] = hex[size-1-i];
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

    printf("0x");

    if (n.number_of_chunks == 0) printf("0");

    // Starting with the most significant chunk in the end of the array and ignore all leading zeros
    for (int i = n.number_of_chunks-1; i >= 0; i--) {
        if (i == n.number_of_chunks-1 && n.chunks[i] == 0){
            chunk_before_is_zero = true;
            continue;
        }
        else if (chunk_before_is_zero && i == 0) {
            printf("0");
        }
        else if (chunk_before_is_zero && n.chunks[i] == 0) {
            continue;
        }
        else if (i == n.number_of_chunks-1) {
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

    int resulting_size = tmp_a.number_of_chunks;
    if (tmp_a.number_of_chunks < tmp_b.number_of_chunks) resulting_size = tmp_b.number_of_chunks;

    result->number_of_chunks = resulting_size;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * resulting_size);

    // One XOR per chunk
    for (int i = 0; i < resulting_size; i++) {
        if (i >= tmp_a.number_of_chunks) {
            result->chunks[i] = tmp_b.chunks[i];
        }
        else if (i >= tmp_b.number_of_chunks) {
            result->chunks[i] = tmp_a.chunks[i];
        }
        else {
            result->chunks[i] = tmp_a.chunks[i] ^ tmp_b.chunks[i];
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
    if (n.chunks[n.number_of_chunks - 1] & (1 << 31)) {
        result->number_of_chunks = tmp_n.number_of_chunks + 1;
    }
    else {
        result->number_of_chunks = tmp_n.number_of_chunks;
    }

    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * result->number_of_chunks);

    // Left shift per chunk
    for (int i = 0; i < result->number_of_chunks; i++) {
        if (i == 0) {
            result->chunks[i] = tmp_n.chunks[i] << 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block before is shifted left to the current block
            result->chunks[i] = (tmp_n.chunks[i] << 1) | (tmp_n.chunks[i-1] >> 31);
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
        if (i == tmp_n.number_of_chunks - 1) {
            result->chunks[i] = tmp_n.chunks[i] >> 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block after is shifted right to the current block
            result->chunks[i] = (tmp_n.chunks[i] >> 1) | (tmp_n.chunks[i+1] << 31);
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
    return n.chunks[0] & 0x1;
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
