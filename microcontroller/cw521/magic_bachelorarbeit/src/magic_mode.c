#include "magic_mode.h"
#include "util_functions.h"
#include "salsa20.h"
#include "galois.h"

#include "stdlib.h"
#include "stdio.h"


const int BLOCKSIZE = 4;


void plaintext_to_ciphertext_blocks(bignum *ciphertext_blocks, char *plaintext, uint32_t key[8], uint32_t nonce[2]) {
    const int number_of_bignums = calculate_number_of_bignums_from_string(plaintext);

    // string to bignum array
    bignum bignum_array_plaintext[number_of_bignums];
    string_to_bignum_array(bignum_array_plaintext, plaintext);

    // bignum array to one uint32_t array
    const int number_of_chunks = number_of_bignums * BLOCKSIZE;
    uint32_t plaintext_hex[number_of_chunks];
    bignum_blocks_to_one_array(plaintext_hex, bignum_array_plaintext, number_of_bignums);

    // encryption
    uint32_t ciphertext_hex[number_of_chunks];
    salsa20_encryption_decryption(key, nonce, plaintext_hex, ciphertext_hex, number_of_chunks);

    uint32_t one_block[BLOCKSIZE];

    // ciphertext array to an array of bignums which represents the several blocks for MAGIC
    for (int i = 0, k = 0; i < number_of_chunks; i++, k++) {
        one_block[i%4] = ciphertext_hex[i];

        // every 128 bits add the bignum to the array with block[0] until block[3]
        if (k == 3) {
            ciphertext_blocks[((i+1)/BLOCKSIZE)-1] = init_bignum(one_block);
            k = -1;  // start again at k = 0
        }
    }
}


void ciphertext_blocks_to_plaintext_as_str(unsigned char *plaintext, bignum ciphertext_blocks[], int number_of_blocks, uint32_t key[8], uint32_t nonce[2]) {
    const int number_of_chunks = number_of_blocks * BLOCKSIZE;

    // bignum array to one uint32_t array
    uint32_t ciphertext_hex[number_of_chunks];
    bignum_blocks_to_one_array(ciphertext_hex, ciphertext_blocks, number_of_blocks);

    // decryption
    uint32_t plaintext_hex[number_of_chunks];
    salsa20_encryption_decryption(key, nonce, ciphertext_hex, plaintext_hex, number_of_chunks);

    // convert to bignum array and ignore leading zeros
    bignum bignum_array_plaintext[number_of_blocks];
    init_bignum_array(bignum_array_plaintext, number_of_blocks, plaintext_hex, number_of_chunks);

    // convert to string
    bignum_array_to_string(plaintext, bignum_array_plaintext, number_of_blocks);
}


bignum find_hash_key_value(int threshold, int number_of_blocks, int max_number_of_tries, uint32_t seed) {
    printf("Tries left: %d\n", max_number_of_tries);
    if (max_number_of_tries == 0) {
        printf("No hash key found. Use different values.\n");
        return init_bignum_to_zero();
    }

    uint32_t key[8];
    uint32_t nonce[2];
    bignum hash_key = random_bignum_key_nonce(key, nonce, seed);
    bignum original_hash_key = copy_bignum(hash_key);

    bignum hash_key_inverse = mult_inverse(hash_key);
    bignum original_hash_key_inverse = copy_bignum(hash_key_inverse);

    for (int threshold_value = 1; threshold_value <= threshold; threshold_value++) {
        bool result = check_hash_key(threshold_value, number_of_blocks, hash_key, original_hash_key, hash_key_inverse, original_hash_key_inverse);

        if (!result) {
            return find_hash_key_value(threshold, number_of_blocks, --max_number_of_tries, seed+42);
        }
    }

    printf("Hash key found.\n");
    return original_hash_key;
}


bignum calculate_input_for_blinding_cipher(bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum authorized_data) {
    bignum hash_key_tmp = copy_bignum(hash_key);
    bignum original_hash_key = copy_bignum(hash_key);
    bignum intermediate_value = init_bignum_to_zero();
    bignum mult_result = init_bignum_to_zero();

    // determine the intermediate_value: intermediate_value = block_1 * hash_key^1 + ... + block_n * hash_key^n
    for (int i = 0; i < number_of_blocks; i++) {
        mult_result = mult(ciphertext_blocks[i], hash_key_tmp);
        intermediate_value = add(intermediate_value, mult_result);
        hash_key_tmp = mult(hash_key_tmp, original_hash_key);
    }

    return add(intermediate_value, authorized_data);
}


bignum ciphertext_blocks_to_tag(bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum authorized_data, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    bignum blinding_cipher_input = calculate_input_for_blinding_cipher(ciphertext_blocks, number_of_blocks, hash_key, authorized_data);

    // encrypt input with the blinding cipher
    uint32_t tag_hex[BLOCKSIZE];
    salsa20_encryption_decryption(blinding_key, blinding_nonce, blinding_cipher_input.chunks, tag_hex, BLOCKSIZE);

    return init_bignum(tag_hex);
}


bignum decrypt_tag(bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    uint32_t intermediate_value[BLOCKSIZE];
    salsa20_encryption_decryption(blinding_key, blinding_nonce, tag.chunks, intermediate_value, BLOCKSIZE);

    return init_bignum(intermediate_value);
}


bignum calculate_syndrome(bignum authorized_data, bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    bignum input = calculate_input_for_blinding_cipher(ciphertext_blocks, number_of_blocks, hash_key, authorized_data);
    bignum decrypted_tag = decrypt_tag(tag, blinding_key, blinding_nonce);

    // syndrome = authorized_data + block_1 * hash_key^1 + ... + block_n * hash_key^n + decrypted_tag
    return add(input, decrypted_tag);
}


int locate_error(bignum syndrome_values[], int number_of_blocks, int threshold) {
    int number_of_errors = 0;
    int error_index = -1;

    // is only one block corrupted?
    for (int i = 0; i < number_of_blocks; i++) {
        if (hamming_weight(syndrome_values[i]) <= threshold) {
            number_of_errors++;
            error_index = i;
        }
        // at least two blocks are corrupted
        if (number_of_errors > 1) {
            return -1;
        }
    }

    // no block is corrupted
    if (number_of_errors == 0) {
        return -1;
    }

    // one block is corrupted
    return error_index;
}


bool can_correct_parity(bignum corrupted_tag, bignum new_tag, int threshold) {
    // result equals the error_vector if new_tag is correct
    // error vector must fulfill this condition
    return hamming_weight(add(corrupted_tag, new_tag)) <= threshold;
}


verify_result verify(bignum authorized_data, bignum ciphertext_blocks[], int number_of_blocks, bignum tag, int threshold, bignum hash_key, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    verify_result result;
    bignum new_tag = ciphertext_blocks_to_tag(ciphertext_blocks, number_of_blocks, hash_key, authorized_data, blinding_key, blinding_nonce);

    // no block is corrupted
    if (are_bignums_equal(new_tag, tag)) {
        bignum bignum_array[1];
        bignum zero = init_bignum_to_zero();
        bignum_array[0] = zero;

        result.correction_successful =  true;
        result.ciphertext_blocks = bignum_array;
        result.tag = init_bignum_to_zero();

        return result;
    }
    else {
        bignum hash_key_inverse = mult_inverse(hash_key);
        bignum original_hash_key_inverse = copy_bignum(hash_key_inverse);

        // calculate syndrome
        bignum syndrome = calculate_syndrome(authorized_data, ciphertext_blocks, number_of_blocks, hash_key, tag, blinding_key, blinding_nonce);
        bignum syndrome_values[number_of_blocks];

        // calculate error location indicators (S_i)
        // S_i = error_vector -> if i == i_err
        for (int i = 0; i < number_of_blocks; i++) {
            syndrome_values[i] = mult(syndrome, hash_key_inverse);
            hash_key_inverse = mult(hash_key_inverse, original_hash_key_inverse);
        }

        // correct one corrupted ciphertext block
        int error_index = locate_error(syndrome_values, number_of_blocks, threshold);
        if (error_index != -1) {
            ciphertext_blocks[error_index] = add(ciphertext_blocks[error_index], syndrome_values[error_index]);

            result.correction_successful = true;
            result.ciphertext_blocks = ciphertext_blocks;
            result.tag = tag;

            return result;
        }
        else {
            // correct error in the tag
            if (can_correct_parity(tag, new_tag, threshold)) {
                result.correction_successful = true;
                result.ciphertext_blocks = ciphertext_blocks;
                result.tag = new_tag;

                return result;
            }
            // uncorrectable error (more than one ciphertext is corrupted)
            else {
                bignum bignum_array[1];
                bignum zero = init_bignum_to_zero();
                bignum_array[0] = zero;

                result.correction_successful = false;
                result.ciphertext_blocks = bignum_array;
                result.tag = init_bignum_to_zero();

                return result;
            }
        }
    }
}
