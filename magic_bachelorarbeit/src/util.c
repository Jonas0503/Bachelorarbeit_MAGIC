#include "util.h"

#include "stdio.h"


void print_array(uint32_t *array, int size) {
    for (int i = 0; i < size; i++) {
        printf("%i ", array[i]);
    }

    printf("\n");
}
