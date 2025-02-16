#include "magic_mode.h"
#include "util.h"
#include "salsa20.h"

#include "stdlib.h"
#include "stdio.h"


const int BLOCKSIZE = 4;


bignum pad(bignum n) {
    if (n.number_of_chunks % 4 == 0) {
        return n;
    }

    int size_new = n.number_of_chunks + (((n.number_of_chunks % BLOCKSIZE) - BLOCKSIZE) * -1);
    uint32_t *hex = malloc(sizeof(uint32_t) * size_new);

    for (int i = 0; i < size_new; i++) {
        if (i < n.number_of_chunks) {
            hex[i] = n.chunks[i];
        }
        else {
            hex[i] = 0x0;
        }
    }

    destroy_bignum(n);

    bignum r = init_bignum(hex, size_new);
    free(hex);

    return r;
}


void plaintext_to_ciphertext_blocks(char *plaintext, char *ciphertext, uint32_t key[8], uint32_t nonce[2]) {
    bignum plaintext_as_bignum = plaintext_to_bignum(plaintext);
    plaintext_as_bignum = pad(plaintext_as_bignum);

    uint32_t *ciphertext_hex = malloc(plaintext_as_bignum.number_of_chunks * sizeof(uint32_t));
    uint32_t *dec = malloc(plaintext_as_bignum.number_of_chunks * sizeof(uint32_t));

    salsa20_encryption_decryption(key, nonce, plaintext_as_bignum.chunks, ciphertext_hex, plaintext_as_bignum.number_of_chunks);
    for (int i = 0; i < plaintext_as_bignum.number_of_chunks; i++) {
        printf("%x ", ciphertext_hex[i]);
    }
    printf("\n");

    salsa20_encryption_decryption(key, nonce, ciphertext_hex, dec, plaintext_as_bignum.number_of_chunks);
    for (int i = 0; i < plaintext_as_bignum.number_of_chunks; i++) {
        printf("%x ", dec[i]);
    }
    printf("\n");
}
