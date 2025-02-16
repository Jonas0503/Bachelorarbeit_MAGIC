#include "stdint.h"
#include "bignum.h"


bignum pad(bignum n);
void plaintext_to_ciphertext_blocks(char *plaintext, char *ciphertext, uint32_t key[8], uint32_t nonce[2]);
