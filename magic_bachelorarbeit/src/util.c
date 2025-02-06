#include "util.h"

#include "string.h"
#include "stdio.h"


// TODO: Polynom erstmal im Voraus berechnen und einfach einsetzen
// Man weiß, wie viele Ziffern ein Polynom der Größe 2^128 haben kann
void polynom_degree_128_to_bignum(bignum *result, int *polynom, int size) {
    char binary_string[polynom[0]+1];
    memset(binary_string, '0', polynom[0]);

    for (int i = 0; i < size; i++) {
        binary_string[polynom[0]-polynom[i]] = '1';
    }

    binary_string[polynom[0]] = '\0';

    printf("%s\n", binary_string);
}
