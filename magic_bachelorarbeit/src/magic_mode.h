#include "stdint.h"
#include "bignum.h"


bignum pad(bignum n);
bignum unpad(bignum n);
bignum *plaintext_to_ciphertext_blocks(char *plaintext, uint32_t key[8], uint32_t nonce[2]);
