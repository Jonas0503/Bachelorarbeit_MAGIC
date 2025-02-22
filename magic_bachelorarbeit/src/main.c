#include "galois.h"
#include "util.h"
#include "bignum.h"
#include "salsa20.h"
#include "magic_mode.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"


int main(int argc, char const *argv[]) {
    char *text = "Hallo WeltHallo WeltHallo WeltHallo WeltHallo WeltHallo WeltHallo Welt";
    const int number_of_bignums = calculate_number_of_bignums_from_string(text);
    bignum array_of_bignums[number_of_bignums];
    for (int i = 0; i < number_of_bignums; i++) {
        array_of_bignums[i] = init_bignum_to_zero();
    }

    string_to_bignum_array(array_of_bignums, text);
    printf("-------------------------------------------------------------\n");
    for (int i = 0; i < number_of_bignums; i++) {
        print_bignum(array_of_bignums[i]);
    }

    const int noc = calculate_number_of_chars_from_bignum_array(array_of_bignums, number_of_bignums);
    unsigned char res[noc];

    bignum_array_to_string(res, array_of_bignums, number_of_bignums);
    printf("%s\n", res);

    return 1;
}
