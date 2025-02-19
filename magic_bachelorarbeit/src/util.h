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

bignum string_to_bignum(char *plaintext);
unsigned char *bignum_to_string(bignum n);
int determine_number_of_ciphertext_blocks(bignum blocks[]);
bignum ciphertext_bignum_blocks_to_one_bignum(bignum ciphertext_blocks[]);
bignum pad(bignum n);
bignum unpad(bignum n);
int hamming_weight(bignum n);
