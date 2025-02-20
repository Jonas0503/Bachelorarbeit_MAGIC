#include "bignum.h"

#include "stdint.h"


/// @brief Allocates the memory for the chunks and checks wether malloc or realloc should be used.
/// @param already_allocated Are the chunks for the bignum n already allocated?
/// @param n The number to be allocated.
/// @param size_in_bytes The size in bytes for the allocation of memory.
/// @return The allocted memory for the chunks of numbers.
uint32_t *allocate_memory_for_chunks(bool already_allocated, bignum *n, int size_in_bytes);

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

/// @brief Converts a string to a bignum in hex values.
/// @param text The string to be converted.
/// @return The bignum which represents the string.
bignum string_to_bignum(char *text);

/// @brief Converts a bignum into a string as a unsigned char* because otherwise its possible that two hex-digits overflow the normal char.
/// @param n The bignum to be converted.
/// @return The string as an unsigned char which represents the bignum n.
unsigned char *bignum_to_string(bignum n);

/// @brief Determines the number of blocks/bignums in the array.
/// @param ciphertext_blocks All blocks/bignums in the array. One bignum represents 128-bit (4 chunks). The array must end with a zero bignum.
/// @return The number of blocks/bignums without the zero at the end.
int calculate_number_of_ciphertext_blocks(bignum ciphertext_blocks[]);

/// @brief Converts all blocks/bignums into one bignum.
/// @param ciphertext_blocks All blocks/bignums in the array. One bignum represents 128-bit (4 chunks). The array must end with a zero bignum.
/// @return The bignum without all chunks joined together.
bignum ciphertext_bignum_blocks_to_one_bignum(bignum ciphertext_blocks[]);

/// @brief Pads the bignum to full 128-bit (4 chunks) by using the procedure in RFC 5652 section 6.3
/// @param result The address of the bignum where the result of the padding is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The bignum to be padded.
void pad(bignum *result, bool already_allocated, bignum n);

/// @brief Unpads which was padded by procedure in RFC 5652 section 6.3
/// @param result The address of the bignum where the result of the unpadding is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The bignum to be unpadded.
void unpad(bignum *result, bool already_allocated, bignum n);

/// @brief Determines the hamming weight of a bignum (number of bits with a 1)
/// @param n The bignum at which the hamming weight should be calculated.
/// @return The hamming weight of bignum n
int hamming_weight(bignum n);

/// @brief Frees all the memory allocated by blocks
/// @param ciphertext_blocks The array from which to free the memory.
/// @param number_of_blocks The size of the array blocks.
void destroy_bignum_array(bignum blocks[], int number_of_blocks);
