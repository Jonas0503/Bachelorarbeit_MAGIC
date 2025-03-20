#include "galois.h"
#include "util_functions.h"
#include "bignum.h"
#include "salsa20.h"
#include "magic_mode.h"
#include "hamming_code.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"


void example_magic_mode() {
    // example
    char *plaintext = "Hallo Welt! Ich bin der Jonas.";
    int threshold = 1;

    uint32_t key[8];
    uint32_t nonce[2];
    random_bignum_key_nonce(key, nonce, 0);

    uint32_t blinding_key[8];
    uint32_t blinding_nonce[2];
    bignum authorized_data = init_bignum_to_zero();
    random_bignum_key_nonce(blinding_key, blinding_nonce, 1);

    const int nob = calculate_number_of_bignums_from_string(plaintext);
    bignum ciphertext_blocks[nob];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, plaintext, key, nonce);

    bignum hash_key = find_hash_key_value(threshold, nob, 3, 0);
    bignum tag = ciphertext_blocks_to_tag(ciphertext_blocks, nob, hash_key, authorized_data, blinding_key, blinding_nonce);

    print_bignum_array(ciphertext_blocks, nob);
    printf("\n");
    ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 42);
    // ciphertext_blocks[0] = one_bit_modification(ciphertext_blocks[0], 100);
    print_bignum_array(ciphertext_blocks, nob);
    printf("\n");

    verify_result res = verify(authorized_data, ciphertext_blocks, nob, tag, threshold, hash_key, blinding_key, blinding_nonce);
    print_bignum_array(res.ciphertext_blocks, nob);
    printf("\n");
    print_bignum(res.tag);
    printf("\n");
}


void example_hamming_code_per_block() {
    char *s = "Hallo Welt";
    int number_of_bignums = calculate_number_of_bignums_from_string(s);
    int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(s);

    uint32_t key[8] = {
        0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
        0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
    };

    uint32_t nonce[2] = {0x0, 0x1};

    bignum ciphertext_blocks[number_of_bignums];
    plaintext_to_ciphertext_blocks(ciphertext_blocks, s, key, nonce);

    print_bignum_array(ciphertext_blocks, number_of_bignums);
    printf("\n");

    bignum blocks_parity[number_of_bignums_parity];
    add_parity_to_bignum_array(blocks_parity, ciphertext_blocks, number_of_bignums, number_of_bignums_parity);

    print_bignum_array(blocks_parity, number_of_bignums_parity);
    printf("\n");

    hc_result res = verify_hamming_code(blocks_parity, number_of_bignums_parity);
    printf("%i\n", res.correction_successful);
    print_bignum(res.ciphertext_blocks_with_parity[0]);
    printf("\n");

    bignum blocks_no_parity[number_of_bignums];
    remove_parity_from_encrypted_ciphertext_blocks(blocks_no_parity, blocks_parity, number_of_bignums_parity, number_of_bignums);
    print_bignum_array(blocks_no_parity, number_of_bignums);
}


int main() {
    // example_magic_mode();
    // example_hamming_code_per_block();
    int start = 50;
    int end = 250;
    int interval = 25;
    int number_of_measurements = 1;

    // this respresents one ciphertext block
    uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

    // 16 chars (ASCII) -> one block
    char *one_block_text = "1234ABCD5678EFGH";

    // iterate over blocks
    for (volatile int i = start; i <= end; i += interval) {
        volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
        // measure the cycle count [number_of_measurements] times
        for (int f = 0; f < number_of_measurements; f++) {
            bignum blocks[i];
            int space_for_text = i * 16;
            char text[space_for_text];

            // fill the blocks and text
            for (int k = 0; k < i; k++) {
                blocks[k] = init_bignum(one_block);
                if (k == 0) {
                    strcpy(text, one_block_text);
                }
                else {
                    strcat(text, one_block_text);
                }
            }

            int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(text);

            volatile bignum blocks_parity[number_of_bignums_parity];
            add_parity_to_bignum_array(blocks_parity, blocks, i, number_of_bignums_parity);
        }

        volatile float avg = average(results, number_of_measurements);
        volatile float sd = standard_deviation(results, number_of_measurements, avg);

        // statement to set a breakpoint for printing
        volatile int PRINT_VALUES = avg;
    }

    return 0;
}
