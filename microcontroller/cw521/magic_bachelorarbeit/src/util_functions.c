#include "util_functions.h"
#include "salsa20.h"
#include "galois.h"

#include "stdlib.h"
#include "string.h"
#include "stdio.h"


// defined in magic_mode.c
extern const int BLOCKSIZE;


void convert_64_bit_into_two_32_bit(uint64_t a, uint32_t *left_part, uint32_t *right_part) {
    uint32_t left_value = (a & 0xffffffff00000000) >> 32;
    uint32_t right_value = a & 0xffffffff;

    (*left_part) = left_value;
    (*right_part) = right_value;
}


uint64_t convert_two_32_bit_into_64_bit(uint32_t left_part, uint32_t right_part) {
    return (((uint64_t)left_part) << 32) | right_part;
}


int calculate_number_of_bignums_from_string(char *text) {
    int plaintext_size = strlen(text);
    int number_of_filled_chunks = ((plaintext_size - 1) / 4) + 1;
    int number_of_bignums = (number_of_filled_chunks + (BLOCKSIZE-1)) / BLOCKSIZE;

    return number_of_bignums;
}


void string_to_bignum_array(bignum *array_of_bignums, char *text) {
    int plaintext_size = strlen(text);
    int number_of_bignums = calculate_number_of_bignums_from_string(text);

    // leading zeros and easier calculations
    for (int i = 0; i < number_of_bignums; i++) {
        array_of_bignums[i] = init_bignum_to_zero();
    }

    // fill up the chunks starting from the back
    int shifts = 0;
    int k = 3;
    int bignum_array_index = number_of_bignums-1;
    int counter = 0;
    for (int i = 0; i < plaintext_size; i++) {
        // one char equals 8 bit
        array_of_bignums[bignum_array_index].chunks[k] = array_of_bignums[bignum_array_index].chunks[k] | (text[plaintext_size-1-i] << shifts);
        shifts += 8;
        // every 32 bit a new chunk
        if (shifts >= 32) {
            shifts = 0;
            k--;
            counter++;
        }
        // every 4 chunks a new bignum
        if (counter == 4) {
            bignum_array_index--;
            k = 3;
            counter = 0;
        }
    }
}


int calculate_number_of_chars_from_bignum_array(bignum *array_of_bignums, int array_size) {
    int number_of_chunks = array_size * BLOCKSIZE;
    int number_of_chars = number_of_chunks * 4;

    // one char -> two hex digits
    // counts the number of resulting chars without the leading zeros
    for (int k = 0; k < array_size; k++) {
        for (int i = 0; i < number_of_chunks; i++) {
            if ((array_of_bignums[k].chunks[i] >> 24) != 0) break;
            if ((array_of_bignums[k].chunks[i] >> 24) == 0) number_of_chars--;
            if (((array_of_bignums[k].chunks[i] >> 16) & 0xff) != 0) break;;
            if (((array_of_bignums[k].chunks[i] >> 16) & 0xff) == 0) number_of_chars--;
            if (((array_of_bignums[k].chunks[i] >> 8) & 0xff) != 0) break;
            if (((array_of_bignums[k].chunks[i] >> 8) & 0xff) == 0) number_of_chars--;
            if ((array_of_bignums[k].chunks[i] & 0xff) != 0) break;
            if ((array_of_bignums[k].chunks[i] & 0xff) == 0) number_of_chars--;
        }
    }

    return number_of_chars + 1;
}


void bignum_array_to_string(unsigned char *string, bignum *array_of_bignums, int array_size) {
    int shifts = 0;
    int chunk_index = 3;
    int counter = 0;
    int bignum_array_index = array_size-1;
    int number_of_chars = calculate_number_of_chars_from_bignum_array(array_of_bignums, array_size);

    // starting at the back of the string because of the leading zeros
    for (int i = number_of_chars-2; i >= 0; i--) {
        string[i] = ((array_of_bignums[bignum_array_index].chunks[chunk_index] >> shifts) & 0xff);
        shifts += 8;
        // every 32 bits a new chunk
        if (shifts >= 32) {
            shifts = 0;
            chunk_index--;
            counter++;
        }
        // every 4 chunks a new bignum
        if (counter == 4) {
            bignum_array_index--;
            counter = 0;
            chunk_index = 3;
        }
    }

    string[number_of_chars-1] = '\0';
}


void bignum_blocks_to_one_array(uint32_t *array, bignum *ciphertext_blocks, int number_of_blocks) {
    // every 128-bit a new chunk gets copied into the array of the resulting bignum
    // ciphertext blocks are always 128-bit (4 chunks)
    for (int i = 0, k = 0; i < number_of_blocks; i++, k += BLOCKSIZE) {
        memcpy(array + k, ciphertext_blocks[i].chunks, sizeof(uint32_t) * BLOCKSIZE);
    }
}


int hamming_weight(bignum n) {
    bignum tmp_n = copy_bignum(n);
    int number_of_ones = 0;

    // looks always at the last bit and increment the counter if its a one
    while (is_bignum_not_zero(tmp_n)) {
        // if a one is the last bit
        if (is_bignum_odd(tmp_n)) {
            number_of_ones++;
        }

        // look at the next bit
        tmp_n = shift_right_by_one_bignum(tmp_n);
    }

    return number_of_ones;
}


bignum random_bignum_key_nonce(uint32_t key_res[8], uint32_t nonce_res[2], uint32_t seed) {
    uint32_t message_in[BLOCKSIZE];
    uint32_t key[8];
    uint32_t nonce[2];

    for(int i = 0; i < 8; i++) {
        key[i] = seed+i;
    }
    for(int i = 0; i < 2; i++) {
        nonce[i] = seed+i;
    }
    for (int i = 0; i < BLOCKSIZE; i++) {
        message_in[i] = seed+i;
    }

    // random number generation
    uint32_t message_out_bignum[BLOCKSIZE];
    salsa20_encryption_decryption(key, nonce, message_in, message_out_bignum, BLOCKSIZE);
    bignum random_bignum = init_bignum(message_out_bignum);

    // random key generation
    nonce[0] = nonce[0]+1;
    salsa20_encryption_decryption(key, nonce, key, key_res, 8);

    // random nonce generation
    nonce[1] = nonce[1]+1;
    salsa20_encryption_decryption(key, nonce, nonce, nonce_res, 2);

    return random_bignum;
}


bignum polynom_to_bignum(int bit_indices[], int size) {
    bignum result = init_bignum_to_zero();
    uint32_t hex[4] = {0x0, 0x0, 0x0, 0x0};

    uint32_t hex_2[4] = {0x0, 0x0, 0x0, 0x2};
    bignum base = init_bignum(hex_2);

    // 2**bit_indices[0] + ... + 2**bit_indices[size-1]
    for (int i = 0; i < size; i++) {
        hex[3] = bit_indices[i];
        result = add(result, power(base, init_bignum(hex)));
    }

    return result;
}


bool check_hash_key(int threshold, int number_of_blocks, bignum hash_key, bignum hash_key_copy, bignum hash_key_inverse, bignum hash_key_inverse_copy) {
    // array for the current combination
    int combination[threshold];
    for (int i = 0; i < threshold; i++) {
        combination[i] = 0;
    }

    int index_combinations = 0;
    int index_bit_indices = 0;

    while (index_combinations >= 0) {

        // forward step as long as both indices does not exceed array lengths
        if (index_bit_indices < 128 && index_combinations < threshold) {

            // set value in the combination array
            combination[index_combinations] = index_bit_indices;

            // if combination array is full do the calculations
            if (index_combinations == threshold-1) {
                bignum error_vector = polynom_to_bignum(combination, threshold);

                // check hash-key
                for (int i = 0; i < number_of_blocks; i++) {
                    if (hamming_weight(mult(error_vector, hash_key_inverse)) <= threshold || hamming_weight(mult(error_vector, hash_key)) <= threshold) {
                        return false;
                    }

                    hash_key = mult(hash_key, hash_key_copy);
                    hash_key_inverse = mult(hash_key_inverse, hash_key_inverse_copy);
                }

                // move forward in the bit indices
                index_bit_indices++;
            }

            // select next bit index
            else {
                index_bit_indices = combination[index_combinations]+1;
                index_combinations++;
            }
        }
        // backward step
        else {
            // gets negative when the last combination was found -> all elements in combination array become 127
            index_combinations--;
            if (index_combinations >= 0) {
                index_bit_indices = combination[index_combinations]+1;
            }
        }
    }

    return true;
}


bignum one_bit_modification(bignum n, int bit_position) {
    bignum result = copy_bignum(n);

    int chunk_position;
    if (bit_position < 32) {
        chunk_position = 3;
    }
    else if (bit_position < 64) {
        chunk_position = 2;
        bit_position = bit_position - 32;
    }
    else if (bit_position < 96) {
        chunk_position = 1;
        bit_position = bit_position - 64;
    }
    else {
        chunk_position = 0;
        bit_position = bit_position - 96;
    }

    result.chunks[chunk_position] ^= (1 << bit_position);

    return result;
}
