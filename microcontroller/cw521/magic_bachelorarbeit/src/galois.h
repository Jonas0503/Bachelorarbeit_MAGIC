#ifndef GALOIS_H
#define GALOIS_H

#include "stdint.h"
#include "bignum.h"


/// @brief Adds two bignums.
/// @param a First number.
/// @param b Second number.
/// @return The addition result in the Galois Field.
bignum add(bignum a, bignum b);


/// @brief Multiply two numbers in a Galois Field using the "russian peasant multiplication".
/// @param a First number.
/// @param b Second number.
/// @return The multiplication result in the Galois Field.
bignum mult(bignum a, bignum b);

/// @brief Calculates the power (base**exponent) in a Galois Field
/// @param base The used base.
/// @param exponent The used exponent.
/// @return The power: base**exponent
bignum power(bignum base, bignum exponent);

/// @brief Calculates the multiplicative inverse of the bignum n (n**-1).
/// @param n The number to find the multiplicative inverse.
/// @return The multiplicative inverse of n.
bignum mult_inverse(bignum n);

#endif
