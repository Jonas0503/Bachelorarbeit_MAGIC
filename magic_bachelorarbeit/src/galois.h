#ifndef GALOIS_H
#define GALOIS_H

#include "stdint.h"
#include "bignum.h"

bignum init_irreducible_polynom_128();
bignum add(bignum a, bignum b);
bignum sub(bignum a, bignum b);
void mult(bignum *result, bool already_allocated, bignum a, bignum b, bignum polynom, int polynom_degree);
void mult_inverse(bignum *result, bool already_allocated, bignum n, bignum polynom, int polynom_degree);

#endif
