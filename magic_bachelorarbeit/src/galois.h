#ifndef GALOIS_H
#define GALOIS_H

#include "stdint.h"
#include "bignum.h"


/// @brief Adds two bignums.
/// @param result The bignum where the result of the addition is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param a First number.
/// @param b Second number.
void add(bignum *result, bool already_allocated, bignum a, bignum b);


/// @brief Subtracts two bignums.
/// @param result The bignum where the result of the subtraction is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param a First number.
/// @param b Second number.
void sub(bignum *result, bool already_allocated, bignum a, bignum b);


/// @brief Multiply two numbers in a Galois Field using the "russian peasant multiplication".
/// @param result The bignum where the result of the multiplication is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param a First number.
/// @param b Second number.
void mult(bignum *result, bool already_allocated, bignum a, bignum b);


/// @brief Calculates the multiplicative inverse of the bignum n (n**-1).
/// @param result The bignum where the result of the inversion is saved.
/// @param already_allocated Is the bignum in result already initialized?
/// @param n The number to find the multiplicative inverse.
void mult_inverse(bignum *result, bool already_allocated, bignum n);

#endif
