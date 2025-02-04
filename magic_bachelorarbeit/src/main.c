#include "galois.h"
#include "util.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"


int main(int argc, char const *argv[])
{
    uint32_t a[] = {1, 2, 3};
    uint32_t b[] = {7, 8};

    uint32_t *r = add(a, b, 3, 2);

    print_array(a, 3);
    print_array(b, 2);
    print_array(r, 3);

    free(r);

    return 0;
}

