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


int main() {
    /* char *text = "ABC ABC ABC";
    int x = number_of_encrypted_ciphertext_blocks_with_parity_all_blocks(text);
    printf("%i\n", x); */

    uint32_t hex[4] = {0xf8521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365};
    bignum blocks_no_parity[1];
    init_bignum_array(blocks_no_parity, 1, hex, 4);
    print_bignum_array(blocks_no_parity, 1);
    printf("\n");

    bignum blocks_parity[2];
    add_parity_all_blocks_to_bignum_array(blocks_parity, blocks_no_parity, 1, 2);
    print_bignum_array(blocks_parity, 2);
    printf("\n");

    blocks_parity[1] = one_bit_modification(blocks_parity[1], 42);
    print_bignum_array(blocks_parity, 2);
    printf("\n");

    hc_result res = verify_hamming_code_all_blocks(blocks_parity, 2);
    print_hc_result(res, 2);
    printf("\n");

    bignum blocks_removed_parity[1];
    remove_parity_all_blocks_from_encrypted_ciphertext_blocks(blocks_removed_parity, blocks_parity, 2, 1);

    print_bignum_array(blocks_removed_parity, 1);

    return 0;
}
