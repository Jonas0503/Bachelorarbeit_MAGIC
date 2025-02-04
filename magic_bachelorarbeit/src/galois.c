#include "galois.h"

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"


uint32_t *add(uint32_t *a, uint32_t *b, int size_a, int size_b) {
    int resulting_size;

    if (size_a < size_b) resulting_size = size_b;
    else if (size_a > size_b) resulting_size = size_a;

    uint32_t *result = malloc(sizeof(uint32_t) * resulting_size);

    for (int i = 0; i < resulting_size; i++) {
        if (i >= size_a) {
            result[i] = b[i];
        }
        else if (i >= size_b) {
            result[i] = a[i];
        }
        else {
            result[i] = a[i] ^ b[i];
        }
    }

    return result;
}


uint32_t *sub(uint32_t *a, uint32_t *b, int size_a, int size_b) {
    return add(a, b, size_a, size_b);
}

