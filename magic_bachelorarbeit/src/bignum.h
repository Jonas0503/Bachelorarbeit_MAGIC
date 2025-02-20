#ifndef BIGNUM_H
#define BIGNUM_H

#include "stdint.h"
#include "stdbool.h"


/// @brief The bignum in form of a struct with a pointer to the chunks with the actual number and the number of chunks.
typedef struct {
    uint32_t *chunks;
    int number_of_chunks;
} bignum;

/// @brief Initializes a bignum with the number of array elements and a hex number array.
/// @param hex An array with 32 bit hex numbers: "0x1fffffffff -> {0x1ff, 0xfffffff}".
/// @param size The number of array elements.
/// @return A new bignum.
bignum init_bignum(uint32_t *hex, int size);


/// @brief Initializes a new bignum to zero (0x0).
/// @return A new bignum initialized to zero with one chunk.
bignum init_bignum_to_zero();


/// @brief An already initialized bignum is set to zero with one chunk.
/// @param n The address of the already initialized bignum.
void set_existing_bignum_to_zero(bignum *n);


/// @brief Initializes a new bignum to one (0x1).
/// @return A new bignum initialized to one with one chunk.
bignum init_bignum_to_one();


/// @brief An already initialized bignum is set to one with one chunk.
/// @param n The address of the already initialized bignum.
void set_existing_bignum_to_one(bignum *n);


/// @brief Frees the allocated chunk of numbers.
/// @param n The number which should be destroyed.
void destroy_bignum(bignum n);


/// @brief Prints the bignum as a hex number with all leading zeros not printed.
/// @param n The bignum to be printed.
void print_bignum(bignum n);


/// @brief XOR two bignums and get the result.
/// @param result The address of the bignum where the result of XOR is saved.
/// @param already_malloc Is the bignum in result already initialized?
/// @param a The bignum to be XORed.
/// @param b The bignum to be XORed.
void xor_bignum(bignum *result, bool already_malloc, bignum a, bignum b);


/// @brief Checks wether the bignum is not zero.
/// @param n The bignum to be checked.
/// @return True if not zero; otherwise False.
bool is_bignum_not_zero(bignum n);


/// @brief Shift the bignum one to the left.
/// @param result The address of the bignum where the result of the left shift is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The bignum to be shifted.
void shift_left_by_one_bignum(bignum *result, bool already_allocated, bignum n);


/// @brief Shift the bignum one to the right.
/// @param result The address of the bignum where the result of the right shift is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The bignum to be shifted.
void shift_right_by_one_bignum(bignum *result, bool already_allocated, bignum n);


/// @brief Shift the bignum x times to the right.
/// @param result The address of the bignum where the result of the right shift is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The bignum to be shifted.
/// @param x The number of right shifts.
void shift_right_by_x_bignum(bignum *result, bool already_allocated, bignum n, int x);


/// @brief Checks wether the bignum is odd.
/// @param n The bignum to be checked.
/// @return True if the bignum is odd; False if the bignum is even.
bool is_bignum_odd(bignum n);


/// @brief Checks wether the bignum is inside a Galois Field with a specific degree.
/// @param n The number to be checked.
/// @param degree The degree of the irreducible polynom for the Galois Field.
/// @return True if the number is inside the Galois Field, otherwise False.
bool is_bignum_inside_galois_field(bignum n, int degree);


/// @brief Copies an existing bignum to a new bignum.
/// @param n The bignum to be copied.
/// @return The copied bignum.
bignum copy_bignum(bignum n);

/// @brief Removes all leading zero chunks at the start of the number.
/// @param result The resulting bignum with leading zero chunks removed.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The number to be modified.
void remove_chunks_with_leading_zeros(bignum *result, bool already_allocated, bignum n);

/// @brief Checks if bignum a and b are equal by comparing the chunk sizes and the content in the chunks.
/// @param a Bignum to compare.
/// @param b Bignum to compare
/// @return True if both have the same chunk size and the same content; false otherwise.
bool are_bignums_equal(bignum a, bignum b);

#endif
