#include "bignum.h"

#include "stdint.h"
#include "stdbool.h"


/// @brief The result after a verification for ciphertext blocks with hamming code.
typedef struct {
    bool correction_successful;
    bool one_bit_error;
    bool two_bit_error;
    bignum *ciphertext_blocks_with_parity;
    bignum tag_with_parity;
} hc_result;


/// @brief Calculates the number of bignums with parity values from the string which gets encrypted.
/// @param text The string for the calculation.
/// @return The number of bignums with parity values in each bignum block.
int calculate_number_of_bignums_with_parity_from_string(char *text);

/// @brief Converts the bignum to an array of bits with space for the parity bits at powers of two.
/// @param bit_arrays The bignum array represented as an array with array of bits. Has space for parity bits in each array. This array contains the result.
/// @param bignum_blocks The bignum array to be converted.
/// @param number_of_bignums The number of bignum blocks without parity.
/// @param number_of_bignums_with_parity The number of bignum blocks with parity.
void bignum_array_to_bit_arrays_with_space_for_parity_bits(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity);

/// @brief Sets the parity bits in each bit array to detect two bit errors and correct a one bit error (even parity).
/// @param bit_arrays The bits arrays with space for the parity bits.
/// @param number_of_bignums_with_parity The number of 128-bit arrays int bit_arrays.
void set_parity_bits(bool bit_arrays[][128], int number_of_bignums_with_parity);

/// @brief Converts the arrays of bits to the corresponding bignum array.
/// @param bignum_array The resulting bignum array.
/// @param number_of_bignums The number of 128-bit arrays.
/// @param bit_arrays The bit arrays to convert.
void bit_arrays_to_bignum_array(bignum *bignum_array, int number_of_bignums, bool bit_arrays[][128]);

/// @brief Add the parity bits to each bignum block.
/// @param bignums_with_parity The resulting bignums with parity values in each bignum.
/// @param bignum_blocks The bignum to add parity values to.
/// @param number_of_bignums The size of bignum_blocks.
/// @param number_of_bignums_with_parity The size of bignums_with_parity.
void add_parity_to_bignum_array(bignum *bignums_with_parity, bignum *bignum_blocks, int number_of_bignums, int number_of_bignums_with_parity);

/// @brief Converts the bignum blocks into the corresponding binary representation.
/// @param bit_arrays The resulting binary representation.
/// @param bignum_blocks The bignum blocks to be converted.
/// @param number_of_bignums The number of bignums in bignum_blocks.
void bignum_array_to_bit_arrays(bool bit_arrays[][128], bignum *bignum_blocks, int number_of_bignums);

/// @brief Checks the bignum blocks with hamming code in each block.
/// @param ciphertext_blocks The blocks which gets verified.
/// @param number_of_bignums The size of ciphertext_blocks.
/// @return The result of the hamming code check in form of a struct.
hc_result verify_hamming_code(bignum *ciphertext_blocks, int number_of_bignums);

/// @brief Converts the bignum array with parity values in each block to a bignum array with all parity values removed.
/// @param blocks_no_parity The resulting bignum array with no parity values.
/// @param ciphertext_blocks_with_parity The current bignum array with parity values in each block.
/// @param number_of_blocks_with_parity The number of blocks with parity values in each block.
/// @param number_of_blocks The number of blocks of the resulting bignum array.
void remove_parity_from_ciphertext_blocks(bignum *blocks_no_parity, bignum *ciphertext_blocks_with_parity, int number_of_blocks_with_parity, int number_of_blocks);

/// @brief Prints each 128-bit block to a new line.
/// @param bit_arrays The bit arrays to be printed.
/// @param number_of_blocks The number of blocks to be printed.
void print_bit_arrays(bool bit_arrays[][128], int number_of_blocks);
