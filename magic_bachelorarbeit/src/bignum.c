#include "bignum.h"
#include "util.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdbool.h"
#include "string.h"


bignum init_bignum(uint32_t hex[4]) {
    bignum n;

    // most significant bytes (MSB) are in chunks[0] and least significant bytes (LSB) are in chunks[size-1]
    for (int i = 0; i < BLOCKSIZE; i++) {
        n.chunks[i] = hex[i];
    }

    return n;
}


void init_bignum_array(bignum *bignum_array, int number_of_bignums, uint32_t *hex, int number_of_chunks) {
    int counter = 0;
    int chunk_index_in_bignum = 3;
    int bignum_index = number_of_bignums-1;

    for (int i = 0; i < number_of_bignums; i++) {
        bignum_array[i] = init_bignum_to_zero();
    }

    for (int i = number_of_chunks-1; i >= 0; i--) {
        bignum_array[bignum_index].chunks[chunk_index_in_bignum] = hex[i];
        chunk_index_in_bignum--;
        counter++;

        // every fourth chunk a new bignum
        if (counter == 4) {
            bignum_index--;
            chunk_index_in_bignum = 3;
            counter = 0;
        }
    }
}


bignum init_bignum_to_zero() {
    bignum n;

    for (int i = 0; i < BLOCKSIZE; i++) {
        n.chunks[i] = 0x0;
    }

    return n;
}


bignum init_bignum_to_one() {
    bignum n = init_bignum_to_zero();
    n.chunks[BLOCKSIZE-1] = 0x1;

    return n;
}


void print_bignum(bignum n) {
    printf("0x");

    // Starting with the most significant chunk at the beginning
    for (int i = 0; i < BLOCKSIZE; i++) {
        printf("%08x", n.chunks[i]);
    }

    printf("\n");
}


bignum xor_bignum(bignum a, bignum b) {
    // copies the bignums because wrong results could occur when the parameters a, b and the return variable are the same
    bignum tmp_a = copy_bignum(a);
    bignum tmp_b = copy_bignum(b);
    bignum result;

    // One XOR per chunk starting at the LSB on the right for each number
    for (int i = 0; i < BLOCKSIZE; i++) {
        result.chunks[i] = tmp_a.chunks[i] ^ tmp_b.chunks[i];
    }

    return result;
}


bool is_bignum_not_zero(bignum n) {
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (n.chunks[i] != 0x0) return true;
    }

    return false;
}


bignum shift_left_by_one_bignum(bignum n) {
    // copies the bignum because wrong results could occur when the parameter n and the return variable are the same
    bignum tmp_n = copy_bignum(n);
    bignum result;

    // Left shift per chunk
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (i == BLOCKSIZE-1) {
            result.chunks[i] = tmp_n.chunks[i] << 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block before is shifted left to the current block
            result.chunks[i] = (tmp_n.chunks[i] << 1) | (tmp_n.chunks[i+1] >> 31);
        }
    }

    return result;
}


bignum shift_right_by_one_bignum(bignum n) {
    // copies the bignum because wrong results could occur when the parameter n and the return variable are the same
    bignum tmp_n = copy_bignum(n);
    bignum result;

    // Right shift per chunk
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (i == 0) {
            result.chunks[i] = tmp_n.chunks[i] >> 1;
        }
        else {
            // Bitwise OR to determine wether a 1 of the block after is shifted right to the current block
            result.chunks[i] = (tmp_n.chunks[i] >> 1) | (tmp_n.chunks[i-1] << 31);
        }
    }

    return result;
}


bool is_bignum_odd(bignum n) {
    return n.chunks[BLOCKSIZE-1] & 0x1;
}


bool is_bignum_inside_galois_field_after_left_shift(bignum n) {
    // If the MSB bit is set the number is outside the Galois Field
    return ((n.chunks[0] >> 31) & 0x1) == 0;
}


bignum copy_bignum(bignum n) {
    return init_bignum(n.chunks);
}


bool are_bignums_equal(bignum a, bignum b) {
    // same content?
    for (int i = 0; i < BLOCKSIZE; i++) {
        if (a.chunks[i] != b.chunks[i]) {
            return false;
        }
    }

    return true;
}
