#include "bignum.h"

#include "stdint.h"


/// @brief Convert a 64-bit value into two 32-bit values.
/// @param a The 64-bit value.
/// @param left_part The address for the result of left side of number a.
/// @param right_part The address for the result of right side of number a.
void convert_64_bit_into_two_32_bit(uint64_t a, uint32_t *left_part, uint32_t *right_part);

/// @brief Convert two 32-bit values into a 64-bit value.
/// @param left_part The 32 bits on the left.
/// @param right_part The 32 bits on the right.
/// @return The 64-bit number as the concatenation of left_part and right_part.
uint64_t convert_two_32_bit_into_64_bit(uint32_t left_part, uint32_t right_part);

/// @brief Calculates the min. number of bignums to represent a string.
/// @param text The string for the calculation.
/// @return The min. number of bignums
const int calculate_number_of_bignums_from_string(const char *text);

/// @brief Converts a string to a bignum array.
/// @param array_of_bignums The resulting bignum array.
/// @param text The string to be converted.
void string_to_bignum_array(bignum *array_of_bignums, const char *text);

/// @brief Calculates the number of chars needed to represent the array_of_bignums.
/// @param array_of_bignums The array of bignums for the calculation.
/// @param array_size The array size.
/// @return The number of chars needed to represent the array_of_bignums.
const int calculate_number_of_chars_from_bignum_array(bignum *array_of_bignums, int array_size);

/// @brief Converts a bignum array into one string.
/// @param string The resulting string.
/// @param array_of_bignums The array which is the base for the string representation.
/// @param array_size The size of the array.
void bignum_array_to_string(unsigned char *string, bignum *array_of_bignums, const int array_size);

/// @brief Converts all blocks/bignums into one array with all chunks joined together.
/// @param array The resulting array.
/// @param ciphertext_blocks All blocks/bignums in the array. One bignum represents 128-bit (4 chunks).
/// @param number_of_blocks The size of the array.
void ciphertext_bignum_blocks_to_one_array(uint32_t *array, bignum *ciphertext_blocks, const int number_of_blocks);

/// @brief Determines the hamming weight of a bignum (number of bits with a 1)
/// @param n The bignum at which the hamming weight should be calculated.
/// @return The hamming weight of bignum n
int hamming_weight(bignum n);

/// @brief Generates a pseudo random bignum by using the Salsa20 cipher.
/// @return A pseudo random bignum.
bignum random_bignum();

/// @brief Converts the polynom to a bignum by using the Galois arithmetic.
/// @param bit_indices The polynom as representation of indices where the bit one is set. Max. value for an index is 127.
/// @param size The number of indices.
/// @return The bignum representation of the polynomial.
bignum polynom_to_bignum(int bit_indices[], int size);
