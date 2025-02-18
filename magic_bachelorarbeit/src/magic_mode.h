#include "stdint.h"
#include "bignum.h"


bignum pad(bignum n);
bignum unpad(bignum n);
bignum *plaintext_to_ciphertext_blocks(char *plaintext, uint32_t key[8], uint32_t nonce[2]);
unsigned char *ciphertext_blocks_to_plaintext_as_str(bignum ciphertext_blocks[], uint32_t key[8], uint32_t nonce[2]);
