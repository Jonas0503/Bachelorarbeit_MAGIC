#ifndef BIGNUM_H
#define BIGNUM_H

#include "stdint.h"
#include "stdbool.h"


// defined in magic_mode.c
extern const int BLOCKSIZE;


/// @brief Representation of a 128-bit number with an uint32_t array of size four.
typedef struct {
    uint32_t chunks[4];
} bignum;


/// @brief Initializes a bignum with four 32-bit numbers in an array.
/// @param hex An array with four 32 bit hex numbers: "0x1fffffffff -> {0x0, 0x0, 0x1ff, 0xfffffff}".
/// @return A new bignum.
bignum init_bignum(uint32_t hex[4]);

/// @brief Initializes a bignum array with the given numbers in hex. Every four numbers in hex a new bignum.
/// @param bignum_array The resulting bignum array.
/// @param number_of_bignums The size of the resulting bignum array.
/// @param hex The numbers to initialize the bignum array.
/// @param number_of_chunks The size of the given hex array.
void init_bignum_array(bignum *bignum_array, int number_of_bignums, uint32_t *hex, int number_of_chunks);

/// @brief Initializes a new bignum to zero (0x0).
/// @return A new bignum initialized to zero with four chunks.
bignum init_bignum_to_zero();

/// @brief Initializes a new bignum to one (0x1).
/// @return A new bignum initialized to one with four chunks.
bignum init_bignum_to_one();

/// @brief Prints the bignum as a hex number.
/// @param n The bignum to be printed.
void print_bignum(bignum n);

/// @brief Prints all bignums from the array.
/// @param array The array of bignums to be printed.
/// @param size The number of bignums in the array.
void print_bignum_array(bignum *array, int size);

/// @brief XOR two bignums and get the result.
/// @param a The bignum to be XORed.
/// @param b The bignum to be XORed.
/// @return The XORed bignum.
bignum xor_bignum(bignum a, bignum b);

/// @brief Checks wether the bignum is not zero.
/// @param n The bignum to be checked.
/// @return True if not zero; otherwise False.
bool is_bignum_not_zero(bignum n);

/// @brief Shift the bignum one to the left with no more chunk added. The MSB is lost.
/// @param n The bignum to be shifted.
/// @return The bignum n shifted left by one.
bignum shift_left_by_one_bignum(bignum n);

/// @brief Shift the bignum one to the right.
/// @param n The bignum to be shifted.
/// @return The bignum n shifted right by one.
bignum shift_right_by_one_bignum(bignum n);

/// @brief Checks wether the bignum is odd.
/// @param n The bignum to be checked.
/// @return True if the bignum is odd; False if the bignum is even.
bool is_bignum_odd(bignum n);

/// @brief Checks wether the bignum is inside a Galois Field after a left shift by one.
/// @param n The number to be checked.
/// @return True if the number is inside the Galois Field after a left shift, otherwise False.
bool is_bignum_inside_galois_field_after_left_shift(bignum n);

/// @brief Copies an existing bignum to a new bignum.
/// @param n The bignum to be copied.
/// @return The copied bignum.
bignum copy_bignum(bignum n);

/// @brief Checks if bignum a and b are equal by comparing the chunk sizes and the content in the chunks.
/// @param a Bignum to compare.
/// @param b Bignum to compare
/// @return True if both have the same chunk size and the same content; false otherwise.
bool are_bignums_equal(bignum a, bignum b);

#endif
