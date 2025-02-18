#include "magic_mode.h"
#include "util.h"
#include "salsa20.h"

#include "stdlib.h"
#include "stdio.h"


const int BLOCKSIZE = 4;


// based on RFC 5652 section 6.3
bignum pad(bignum n) {
    int size_new = n.number_of_chunks + (((n.number_of_chunks % BLOCKSIZE) - BLOCKSIZE) * -1);
    uint32_t *hex = malloc(sizeof(uint32_t) * size_new);

    for (int i = 0; i < size_new; i++) {
        if (i < n.number_of_chunks) {
            hex[i] = n.chunks[i];
        }
        else {
            hex[i] = size_new - n.number_of_chunks;
        }
    }

    bignum r = init_bignum(hex, size_new);
    free(hex);

    return r;
}


// based on RFC 5652 section 6.3
bignum unpad(bignum n) {
    int size;
    for (size = 0; size < n.number_of_chunks; size++) {
        if (n.chunks[size] == 0x4 || n.chunks[size] == 0x3 || n.chunks[size] == 0x2 || n.chunks[size] == 0x1) break;
    }

    uint32_t *hex = malloc(sizeof(uint32_t) * size);
    for (int i = 0; i < size; i++) {
        hex[i] = n.chunks[i];
    }

    bignum r = init_bignum(hex, size);
    free(hex);

    return r;
}


bignum *plaintext_to_ciphertext_blocks(char *plaintext, uint32_t key[8], uint32_t nonce[2]) {
    // padding to get full blocks
    bignum plaintext_as_bignum = string_to_bignum(plaintext);
    bignum plaintext_as_bignum_padded = pad(plaintext_as_bignum);

    // encryption
    uint32_t *ciphertext_hex = malloc(plaintext_as_bignum_padded.number_of_chunks * sizeof(uint32_t));
    salsa20_encryption_decryption(key, nonce, plaintext_as_bignum_padded.chunks, ciphertext_hex, plaintext_as_bignum_padded.number_of_chunks);

    int number_of_blocks = plaintext_as_bignum_padded.number_of_chunks / BLOCKSIZE;
    bignum *ciphertext_blocks = malloc(sizeof(bignum) * (number_of_blocks + 1));  // number_of_blocks + zero bignum at the end
    uint32_t *one_block = malloc(sizeof(uint32_t) * BLOCKSIZE);

    // ciphertext array to an array of bignums which represents the several blocks for MAGIC
    for (int i = 0, k = 0; i < plaintext_as_bignum_padded.number_of_chunks; i++, k++) {
        one_block[i%4] = ciphertext_hex[i];

        // every 128 bits add the bignum to the array with block[0] until block[3]
        if (k == 3) {
            bignum bignum_block = init_bignum(one_block, BLOCKSIZE);
            ciphertext_blocks[((i+1)/BLOCKSIZE)-1] = bignum_block;
            k = -1;  // start again at k = 0
        }
    }

    // add a zero bignum at the end -> possible to loop over the ciphertext blocks by checking the number_of_chunks == BLOCKSIZE
    ciphertext_blocks[number_of_blocks] = init_bignum_to_zero();

    destroy_bignum(plaintext_as_bignum);
    destroy_bignum(plaintext_as_bignum_padded);
    free(ciphertext_hex);
    free(one_block);

    return ciphertext_blocks;
}


unsigned char *ciphertext_blocks_to_plaintext_as_str(bignum ciphertext_blocks[], uint32_t key[8], uint32_t nonce[2]) {
    int number_of_blocks = determine_number_of_ciphertext_blocks(ciphertext_blocks);

    uint32_t *plaintext = malloc(sizeof(uint32_t) * (number_of_blocks * BLOCKSIZE));
    bignum ciphertext = ciphertext_bignum_blocks_to_one_bignum(ciphertext_blocks);

    salsa20_encryption_decryption(key, nonce, ciphertext.chunks, plaintext, ciphertext.number_of_chunks);

    bignum plaintext_as_bignum = init_bignum(plaintext, ciphertext.number_of_chunks);
    bignum plaintext_unpadded = unpad(plaintext_as_bignum);

    print_bignum(plaintext_unpadded);

    unsigned char *text = bignum_to_string(plaintext_unpadded);

    destroy_bignum(plaintext_as_bignum);
    destroy_bignum(plaintext_unpadded);
    destroy_bignum(ciphertext);
    free(plaintext);

    return text;
}
