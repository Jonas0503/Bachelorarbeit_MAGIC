#include "bignum.h"

#include "stdint.h"


/// @brief Allocates the memory for the chunks and checks wether malloc or realloc should be used.
/// @param already_allocated Are the chunks for the bignum n already allocated?
/// @param n The number to be allocated.
/// @param size_in_bytes The size in bytes for the allocation of memory.
/// @return The allocted memory for the chunks of numbers.
uint32_t *allocate_memory_for_chunks(bool already_allocated, bignum *n, int size_in_bytes);


void print_internal_state(uint32_t state[16]);
void convert_64_bit_into_two_32_bit(uint64_t a, uint32_t *b, uint32_t *c);
uint64_t convert_two_32_bit_into_64_bit(uint32_t left_part, uint32_t right_part);
