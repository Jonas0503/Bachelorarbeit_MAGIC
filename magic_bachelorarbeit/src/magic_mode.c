#include "magic_mode.h"
#include "util.h"
#include "salsa20.h"
#include "galois.h"

#include "stdlib.h"
#include "stdio.h"


const int BLOCKSIZE = 4;


bignum *plaintext_to_ciphertext_blocks(char *plaintext, uint32_t key[8], uint32_t nonce[2]) {
    // padding to get full blocks
    bignum plaintext_as_bignum = string_to_bignum(plaintext);
    pad(&plaintext_as_bignum, true, plaintext_as_bignum);

    // encryption
    uint32_t *ciphertext_hex = malloc(plaintext_as_bignum.number_of_chunks * sizeof(uint32_t));
    salsa20_encryption_decryption(key, nonce, plaintext_as_bignum.chunks, ciphertext_hex, plaintext_as_bignum.number_of_chunks);

    int number_of_blocks = plaintext_as_bignum.number_of_chunks / BLOCKSIZE;
    bignum *ciphertext_blocks = malloc(sizeof(bignum) * (number_of_blocks + 1));  // number_of_blocks + zero bignum at the end
    uint32_t *one_block = malloc(sizeof(uint32_t) * BLOCKSIZE);

    // ciphertext array to an array of bignums which represents the several blocks for MAGIC
    for (int i = 0, k = 0; i < plaintext_as_bignum.number_of_chunks; i++, k++) {
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
    free(ciphertext_hex);
    free(one_block);

    return ciphertext_blocks;
}


unsigned char *ciphertext_blocks_to_plaintext_as_str(bignum ciphertext_blocks[], uint32_t key[8], uint32_t nonce[2]) {
    int number_of_blocks = calculate_number_of_ciphertext_blocks(ciphertext_blocks);

    uint32_t *plaintext = malloc(sizeof(uint32_t) * (number_of_blocks * BLOCKSIZE));
    bignum ciphertext = ciphertext_bignum_blocks_to_one_bignum(ciphertext_blocks);

    // decryption
    salsa20_encryption_decryption(key, nonce, ciphertext.chunks, plaintext, ciphertext.number_of_chunks);

    // convert to bignum and remove padding
    bignum plaintext_as_bignum = init_bignum(plaintext, ciphertext.number_of_chunks);
    unpad(&plaintext_as_bignum, true, plaintext_as_bignum);

    // convert to string
    unsigned char *text = bignum_to_string(plaintext_as_bignum);

    destroy_bignum(plaintext_as_bignum);
    destroy_bignum(ciphertext);
    free(plaintext);

    return text;
}


bignum find_hash_key_value(int threshold, int number_of_blocks) {
    // TODO
    // 221385673651417484972498539470727584786
    uint32_t hex_for_hash_key[] = {0xa68d546e, 0xb6c431b9, 0x78f700db, 0xca6a9c12};

    bignum hash_key = init_bignum(hex_for_hash_key, 4);
    bignum original_hash_key = copy_bignum(hash_key);

    // bignum hash_key_inverse;
    // mult_inverse(&hash_key_inverse, false, hash_key);
    // bignum original_hash_key_inverse = copy_bignum(hash_key_inverse);


    return original_hash_key;
}


bignum calculate_input_for_blinding_cipher(bignum ciphertext_blocks[], bignum hash_key, bignum authorized_data) {
    bignum hash_key_tmp = copy_bignum(hash_key);
    bignum original_hash_key = copy_bignum(hash_key);
    bignum intermediate_value = init_bignum_to_zero();
    bignum mult_result = init_bignum_to_zero();

    // determine the intermediate_value: intermediate_value = block_1 * hash_key^1 + ... + block_n * hash_key^n
    int number_of_blocks = calculate_number_of_ciphertext_blocks(ciphertext_blocks);
    for (int i = 0; i < number_of_blocks; i++) {
        mult(&mult_result, true, ciphertext_blocks[i], hash_key_tmp);
        add(&intermediate_value, true, intermediate_value, mult_result);
        mult(&hash_key_tmp, true, hash_key_tmp, original_hash_key);
    }

    // input with authorized data
    bignum blinding_cipher_input;
    add(&blinding_cipher_input, false, intermediate_value, authorized_data);

    destroy_bignum(hash_key_tmp);
    destroy_bignum(original_hash_key);
    destroy_bignum(intermediate_value);
    destroy_bignum(mult_result);

    return blinding_cipher_input;
}


bignum ciphertext_blocks_to_tag(bignum ciphertext_blocks[], bignum hash_key, bignum authorized_data, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    bignum blinding_cipher_input = calculate_input_for_blinding_cipher(ciphertext_blocks, hash_key, authorized_data);

    // encrypt input with the blinding cipher
    uint32_t *tag_hex = malloc(sizeof(uint32_t) * BLOCKSIZE);
    salsa20_encryption_decryption(blinding_key, blinding_nonce, blinding_cipher_input.chunks, tag_hex, BLOCKSIZE);

    bignum tag = init_bignum(tag_hex, BLOCKSIZE);

    destroy_bignum(blinding_cipher_input);
    free(tag_hex);

    return tag;
}


bignum decrypt_tag(bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    uint32_t *intermediate_value = malloc(sizeof(uint32_t) * BLOCKSIZE);
    salsa20_encryption_decryption(blinding_key, blinding_nonce, tag.chunks, intermediate_value, BLOCKSIZE);

    bignum result = init_bignum(intermediate_value, BLOCKSIZE);
    free(intermediate_value);

    return result;
}


bignum calculate_syndrome(bignum authorized_data, bignum ciphertext_blocks[], bignum hash_key, bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    bignum input = calculate_input_for_blinding_cipher(ciphertext_blocks, hash_key, authorized_data);
    bignum decrypted_tag = decrypt_tag(tag, blinding_key, blinding_nonce);

    // syndrome = authorized_data + block_1 * hash_key^1 + ... + block_n * hash_key^n + decrypted_tag
    bignum syndrome;
    add(&syndrome, false, input, decrypted_tag);

    destroy_bignum(input);
    destroy_bignum(decrypted_tag);

    return syndrome;
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
    bignum result;
    add(&result, false, corrupted_tag, new_tag);

    // error vector must fulfill this condition
    if (hamming_weight(result) <= threshold) {
        destroy_bignum(result);
        return true;
    }
    else {
        destroy_bignum(result);
        return false;
    }
}


verify_result verify(bignum authorized_data, bignum ciphertext_blocks[], bignum tag, int threshold, bignum hash_key, uint32_t blinding_key[8], uint32_t blinding_nonce[2]) {
    verify_result result;
    bignum new_tag = ciphertext_blocks_to_tag(ciphertext_blocks, hash_key, authorized_data, blinding_key, blinding_nonce);

    // no block is corrupted
    if (are_bignums_equal(new_tag, tag)) {
        result.correction_successful =  true;
        result.ciphertext = "";
        result.tag = "";

        destroy_bignum(new_tag);

        return result;
    }
    else {
        bignum hash_key_inverse;
        mult_inverse(&hash_key_inverse, false, hash_key);
        bignum original_hash_key_inverse = copy_bignum(hash_key_inverse);

        // calculate syndrome
        int number_of_blocks = calculate_number_of_ciphertext_blocks(ciphertext_blocks);
        bignum syndrome = calculate_syndrome(authorized_data, ciphertext_blocks, hash_key, tag, blinding_key, blinding_nonce);
        bignum *syndrome_values = malloc(sizeof(bignum) * number_of_blocks);

        // calculate error location indicators (S_i)
        // S_i = error_vector -> if i == i_err
        for (int i = 0; i < number_of_blocks; i++) {
            mult(&syndrome_values[i], false, syndrome, hash_key_inverse);
            mult(&hash_key, true, hash_key_inverse, original_hash_key_inverse);
        }

        destroy_bignum(syndrome);
        destroy_bignum(hash_key_inverse);
        destroy_bignum(original_hash_key_inverse);

        // correct one corrupted ciphertext block
        int error_index = locate_error(syndrome_values, number_of_blocks, threshold);
        if (error_index != -1) {
            add(&ciphertext_blocks[error_index], true, ciphertext_blocks[error_index], syndrome_values[error_index]);
            bignum ciphertext = ciphertext_bignum_blocks_to_one_bignum(ciphertext_blocks);

            result.correction_successful = true;
            result.ciphertext = (char *)bignum_to_string(ciphertext);
            result.tag = (char *)bignum_to_string(tag);

            destroy_bignum(ciphertext);
            destroy_bignum_array(syndrome_values, number_of_blocks);

            return result;
        }
        else {
            destroy_bignum_array(syndrome_values, number_of_blocks);

            // correct error in the tag
            if (can_correct_parity(tag, new_tag, threshold)) {
                result.correction_successful = true;
                result.ciphertext = (char *)bignum_to_string(ciphertext_bignum_blocks_to_one_bignum(ciphertext_blocks));
                result.tag = (char *)bignum_to_string(new_tag);

                destroy_bignum(new_tag);

                return result;
            }
            // uncorrectable error (more than one ciphertext is corrupted)
            else {
                result.correction_successful = false;
                result.ciphertext = "";
                result.tag = "";

                destroy_bignum(new_tag);

                return result;
            }
        }
    }
}
