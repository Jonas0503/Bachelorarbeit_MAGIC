#ifndef GALOIS_H
#define GALOIS_H

#include "stdint.h"
#include "bignum.h"

bignum init_polynom();
bignum add(bignum a, bignum b);
bignum sub(bignum a, bignum b);
bignum mult(bignum a, bignum b, bignum polynom, int polynom_degree);

#endif
