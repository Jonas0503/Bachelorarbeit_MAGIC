#include "stdint.h"


uint32_t shift_left_and_rotate(uint32_t value, int number_of_shifts);
void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
void rowround(uint32_t state[16]);
void columnround(uint32_t state[16]);
void doubleround(uint32_t state[16]);
uint32_t littleendian(uint32_t word);
void salsa20_hash(uint32_t state_in[16], uint32_t state_out[16]);
void salsa20_expansion(uint32_t state_in[16], uint32_t state_out[16], uint32_t key[8], uint32_t nonce[4]);
void salsa20_encryption(uint32_t key[8], uint32_t nonce[2], uint64_t starting_position, uint32_t *message_in, uint32_t *message_out, uint64_t message_length);
