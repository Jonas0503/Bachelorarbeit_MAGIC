#ifndef MAGIC_H
#define MAGIC_H

#include "bignum.h"

#include "stdint.h"
#include "stdbool.h"


typedef struct {
    bool correction_successful;
    char *ciphertext;
    char *tag;
} verify_result;


bignum *plaintext_to_ciphertext_blocks(char *plaintext, uint32_t key[8], uint32_t nonce[2]);
unsigned char *ciphertext_blocks_to_plaintext_as_str(bignum ciphertext_blocks[], uint32_t key[8], uint32_t nonce[2]);
bignum find_hash_key_value(int threshold, int number_of_blocks);
bignum determine_input_for_blinding_cipher(bignum ciphertext_blocks[], bignum hash_key, bignum authorized_data);
bignum ciphertext_blocks_to_tag(bignum ciphertext_blocks[], bignum hash_key, bignum authorized_data, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);
bignum decrypt_tag(bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);
bignum calculate_syndrome(bignum authorized_data, bignum ciphertext_blocks[], bignum hash_key, bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);
int locate_error(bignum syndrome_values[], int number_of_blocks, int threshold);
bool can_correct_parity(bignum corrupted_tag, bignum new_tag, int threshold);
verify_result verify(bignum authorized_data, bignum ciphertext_blocks[], bignum tag, int threshold, bignum hash_key, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);

#endif
