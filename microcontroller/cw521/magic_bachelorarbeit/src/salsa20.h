#include "stdint.h"


/// @brief Shift the number to the left x bits and add them back on the right.
/// @param value The number to be shifted and rotated.
/// @param number_of_shifts The number of left shifts.
/// @return value <<< number_of_shifts
uint32_t shift_left_and_rotate(uint32_t value, int number_of_shifts);

/// @brief The actual operations for Salsa20 and the returned values are in the function parameters.
/// @param a The address of a with the a value before and then to save the result of a there afterwards.
/// @param b The address of b with the b value before and then to save the result of b there afterwards.
/// @param c The address of c with the b value before and then to save the result of c there afterwards.
/// @param d The address of d with the b value before and then to save the result of d there afterwards.
void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);

/// @brief Four quarter rounds for each row in the 4x4 state.
/// @param state The input state which gets directly updated. The state is a 16 32-bit array which can be interpreted as 4x4 field.
void rowround(uint32_t state[16]);

/// @brief Four quarter rounds for each column in the 4x4 state.
/// @param state The input state which gets directly updated. The state is a 16 32-bit array which can be interpreted as 4x4 field.
void columnround(uint32_t state[16]);

/// @brief A column round followed by a rowround
/// @param state The input state which gets directly updated. The state is a 16 32-bit array which can be interpreted as 4x4 field.
void doubleround(uint32_t state[16]);

/// @brief Converts a 32-bit word/number into littleendian. (littleendian(0x091e4b56) = 0x564b1e09)
/// @param word 32-bit number (block/array position in Salsa20)
/// @return littleendian(0x091e4b56) = 0x564b1e09
uint32_t littleendian(uint32_t word);

/// @brief Executes doubleround() 10 times with state_in converted into little endian.
/// @param state_in The input state which is converted into little endian.
/// @param state_out The state after 10 doublerounds() and addition with state_in and converted back into big endian.
void salsa20_hash(uint32_t state_in[16], uint32_t state_out[16]);

/// @brief Initializes the state and executes salsa20_hash afterwards.
/// @param state_in The input state which gets initialized. Actual input value is not relevant.
/// @param state_out The state after the salsa20_hash() execution.
/// @param key The secret key which is used for the initialization.
/// @param nonce The secret nonce which is used for the initialization.
void salsa20_expansion(uint32_t state_in[16], uint32_t state_out[16], uint32_t key[8], uint32_t nonce[4]);

/// @brief The actual encryption/decryption of a message with Salsa20. This function should be used.
/// @param key The secret key which is used for the initialization.
/// @param nonce The secret nonce which is used for the initialization. A new nonce for every new message should be used.
/// @param message_in The message (plaintext/ciphertext) to be XORed with the state.
/// @param message_out The encrypted/decrypted message.
/// @param message_length The size of the input message array.
void salsa20_encryption_decryption(uint32_t key[8], uint32_t nonce[2], uint32_t *message_in, uint32_t *message_out, uint64_t message_length);

/// @brief Determines the position in the stream of states.
/// @param position The old position.
/// @param nonce_with_position The nonce with the position. The last two fields are for the position.
/// @param loop_index The index of the actual block in the state. Increases with a new state and does not start back at zero.
/// @return The new position.
uint64_t update_position(uint64_t position, uint32_t nonce_with_position[4], int loop_index);

/// @brief Prints the state of Salsa.
/// @param state The state to be printed.
void print_internal_state_of_salsa(uint32_t state[16]);
