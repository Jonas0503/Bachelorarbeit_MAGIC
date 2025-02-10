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
    n.chunks = calloc(size, sizeof(uint32_t));

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


bignum init_bignum_to_one() {
    bignum n;

    n.number_of_chunks = 1;
    n.chunks = malloc(sizeof(uint32_t));
    n.chunks[0] = 0x1;

    return n;
}


void destroy_bignum(bignum n) {
    free(n.chunks);
}


void print_bignum(bignum n) {
    printf("0x");
    if (n.number_of_chunks == 0) printf("0");

    for (int i = n.number_of_chunks-1; i >= 0; i--) {
        if (i == n.number_of_chunks-1 && n.chunks[i] == 0) continue;
        if (i == n.number_of_chunks-1) {
            printf("%x", n.chunks[i]);
        }
        else {
            printf("%08x", n.chunks[i]);
        }
    }

    printf("\n");
}


void xor_bignum(bignum *result, bool already_allocated, bignum a, bignum b) {
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);

    int resulting_size = tmp_a.number_of_chunks;

    if (tmp_a.number_of_chunks < tmp_b.number_of_chunks) resulting_size = tmp_b.number_of_chunks;

    result->number_of_chunks = resulting_size;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * resulting_size);

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


bool is_bignum_zero(bignum n) {
    if (n.number_of_chunks == 0) return false;

    for (int i = 0; i < n.number_of_chunks; i++) {
        if (n.chunks[i] != 0x0) return true;
    }

    return false;
}


void shift_left_by_one_bignum(bignum *result, bool already_allocated, bignum n) {
    bignum tmp_n = copy_bignum(n);

    if (n.chunks[n.number_of_chunks - 1] & (1 << 31)) {
        result->number_of_chunks = tmp_n.number_of_chunks + 1;
    }
    else {
        result->number_of_chunks = tmp_n.number_of_chunks;
    }

    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * result->number_of_chunks);

    for (int i = 0; i < result->number_of_chunks; i++) {
        if (i == 0) {
            result->chunks[i] = tmp_n.chunks[i] << 1;
        }
        else {
            result->chunks[i] = (tmp_n.chunks[i] << 1) | (tmp_n.chunks[i-1] >> 31);
        }
    }

    destroy_bignum(tmp_n);
}


void shift_right_by_one_bignum(bignum *result, bool already_allocated, bignum n) {
    bignum tmp_n = copy_bignum(n);

    result->number_of_chunks = tmp_n.number_of_chunks;
    result->chunks = allocate_memory_for_chunks(already_allocated, result, sizeof(uint32_t) * tmp_n.number_of_chunks);

    for (int i = 0; i < tmp_n.number_of_chunks; i++) {
        if (i == tmp_n.number_of_chunks - 1) {
            result->chunks[i] = tmp_n.chunks[i] >> 1;
        }
        else {
            result->chunks[i] = (tmp_n.chunks[i] >> 1) | (tmp_n.chunks[i+1] << 31);
        }
    }

    destroy_bignum(tmp_n);
}


void shift_right_by_x_bignum(bignum *result, bool already_allocated, bignum n, int x) {
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
    shift_right_by_x_bignum(&x, false, n, degree);
    bool result =  !is_bignum_zero(x);
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
