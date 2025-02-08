#include "bignum.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdbool.h"
#include "string.h"


bignum bignum_init(uint32_t *hex, int size) {
    bignum n;
    n.number_of_chunks = size;
    n.chunks = calloc(size, sizeof(uint32_t));

    for (int i = 0; i < size; i++) {
        n.chunks[i] = hex[size-1-i];
    }

    return n;
}


bignum bignum_init_zero() {
    bignum n;

    n.number_of_chunks = 1;
    n.chunks = malloc(sizeof(uint32_t));
    n.chunks[0] = 0x0;

    return n;
}


bignum bignum_init_one() {
    bignum n;

    n.number_of_chunks = 1;
    n.chunks = malloc(sizeof(uint32_t));
    n.chunks[0] = 0x1;

    return n;
}


void bignum_destroy(bignum n) {
    free(n.chunks);
}


void bignum_print(bignum n) {
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


bignum bignum_xor(bignum a, bignum b) {
    bignum result;
    int resulting_size = a.number_of_chunks;

    if (a.number_of_chunks < b.number_of_chunks) resulting_size = b.number_of_chunks;

    result.number_of_chunks = resulting_size;
    result.chunks = malloc(sizeof(uint32_t) * resulting_size);

    for (int i = 0; i < resulting_size; i++) {
        if (i >= a.number_of_chunks) {
            result.chunks[i] = b.chunks[i];
        }
        else if (i >= b.number_of_chunks) {
            result.chunks[i] = a.chunks[i];
        }
        else {
            result.chunks[i] = a.chunks[i] ^ b.chunks[i];
        }
    }

    return result;
}


bignum bignum_and(bignum a, bignum b) {
    bignum result;
    int resulting_size = a.number_of_chunks;

    if (a.number_of_chunks < b.number_of_chunks) resulting_size = b.number_of_chunks;

    result.number_of_chunks = resulting_size;
    result.chunks = malloc(sizeof(uint32_t) * resulting_size);

    for (int i = 0; i < resulting_size; i++) {
        if (i >= a.number_of_chunks || i >= b.number_of_chunks) {
            result.chunks[i] = 0x0;
        }
        else {
            result.chunks[i] = a.chunks[i] & b.chunks[i];
        }
    }

    return result;
}


bool bignum_is_not_zero(bignum n) {
    if (n.number_of_chunks == 0) return false;

    for (int i = 0; i < n.number_of_chunks; i++) {
        if (n.chunks[i] != 0x0) return true;
    }

    return false;
}


bignum bignum_shift_left_by_one(bignum n) {
    bignum result;

    if (n.chunks[n.number_of_chunks - 1] & (1 << 31)) {
        result.number_of_chunks = n.number_of_chunks + 1;
    }
    else {
        result.number_of_chunks = n.number_of_chunks;
    }

    result.chunks = malloc(sizeof(uint32_t) * result.number_of_chunks);

    for (int i = 0; i < result.number_of_chunks; i++) {
        if (i == 0) {
            result.chunks[i] = n.chunks[i] << 1;
        }
        else {
            result.chunks[i] = (n.chunks[i] << 1) | (n.chunks[i-1] >> 31);
        }
    }

    return result;
}


static bignum bignum_shift_right_by_one_internal(bignum n, int iteration) {
    bignum result;

    result.number_of_chunks = n.number_of_chunks;
    if (iteration == 0) {
        result.chunks = malloc(sizeof(uint32_t) * n.number_of_chunks);
    }

    for (int i = 0; i < n.number_of_chunks; i++) {
        if (i == n.number_of_chunks - 1) {
            result.chunks[i] = n.chunks[i] >> 1;
        }
        else {
            result.chunks[i] = (n.chunks[i] >> 1) | (n.chunks[i+1] << 31);
        }
    }

    return result;
}


bignum bignum_shift_right_by_one(bignum n) {
    return bignum_shift_right_by_one_internal(n, 0);
}


bignum bignum_shift_right_by_x(bignum n, int x) {
    bignum result;

    bignum tmp_n;
    tmp_n.number_of_chunks = n.number_of_chunks;
    tmp_n.chunks = malloc(sizeof(uint32_t) * n.number_of_chunks);
    memcpy(tmp_n.chunks, n.chunks, sizeof(uint32_t) * n.number_of_chunks);

    for (int i = 0; i < x; i++) {
        result = bignum_shift_right_by_one_internal(tmp_n, i);
        tmp_n.number_of_chunks = result.number_of_chunks;
        memcpy(tmp_n.chunks, result.chunks, sizeof(uint32_t) * n.number_of_chunks);
    }

    free(tmp_n.chunks);

    return result;
}


bool bignum_is_odd(bignum n) {
    return n.chunks[0] & 0x1;
}


bool bignum_is_inside_galois_field(bignum n, int degree) {
    bignum x = bignum_shift_right_by_x(n, degree);
    return !bignum_is_not_zero(x);
}
