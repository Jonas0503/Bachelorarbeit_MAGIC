#include "bignum.h"
#include "magic_mode.h"

#include "stdint.h"
#include "stdbool.h"


int calculate_number_of_bignums_with_parity_from_string(char *text);

void bignum_array_to_bit_arrays_with_space_for_parity_bits(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity);

void set_parity_bits(bool bit_arrays[][128], int number_of_bignums_with_parity);

void bit_arrays_to_bignum_array(bignum *bignums_with_parity, int number_of_bignums_with_parity, bool bit_arrays[][128]);

void add_parity_to_bignum_array(bignum *bignums_with_parity, bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity);

void bignum_array_to_bit_arrays(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums_with_parity);

verify_result verify_hamming_code(bignum *ciphertext_blocks, int number_of_bignums_with_parity, bignum tag);
