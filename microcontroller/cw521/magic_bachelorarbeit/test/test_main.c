#include "test_bignum.h"
#include "test_galois.h"
#include "test_hamming_code.h"
#include "test_magic_mode.h"
#include "test_salsa20.h"
#include "test_util_functions.h"

int main() {
    run_tests_bignum();
    run_tests_galois();
    run_tests_hamming_code();
    run_tests_magic_mode();
    run_tests_salsa20();
    run_tests_util_functions();
}