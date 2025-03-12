#ifndef MAGIC_H
#define MAGIC_H

#include "bignum.h"

#include "stdint.h"
#include "stdbool.h"


/// @brief The return type for the verify function.
typedef struct {
    bool correction_successful;
    bignum *ciphertext_blocks;
    bignum tag;
} verify_result;


/// @brief Finds a given hash key by using a random hash key and then checking if it passes the tests.
/// @param threshold The max. number of one-bits in an error_vector.
/// @param number_of_blocks The number of blocks which got encrypted.
/// @param max_number_of_tries The max number of tries to check a random hash-key with the given values.
/// @param seed A seed value to find a random hash key.
/// @return The correct hash key if it was successful; otherwise zero.
bignum find_hash_key_value(int threshold, int number_of_blocks, int max_number_of_tries, uint32_t seed);

/// @brief Determines the input for the blinding cipher.
/// @param ciphertext_blocks The ciphertext blocks with 4 chunks (128-bit) each and with a zero block at the end to calculate the number of blocks.
/// @param number_of_blocks The size of the ciphertext array.
/// @param hash_key A hash key determined by the function find_hash_key().
/// @param authorized_data Additional data which is not encrypted (max. 4 chunks).
/// @return The calculated input for the blinding cipher.
bignum calculate_input_for_blinding_cipher(bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum authorized_data);

/// @brief Calculates the tag by using a blinding cipher.
/// @param ciphertext_blocks The ciphertext blocks with 4 chunks (128-bit) each and with a zero block at the end to calculate the number of blocks.
/// @param number_of_blocks The size of the ciphertext array.
/// @param hash_key A hash key determined by the function find_hash_key().
/// @param authorized_data Additional data which is not encrypted (max. 4 chunks).
/// @param blinding_key A key for the blinding cipher. Must be different then the key for the plaintext encryption.
/// @param blinding_nonce A nonce for the blinding cipher. Must be different then the nonce for the plaintext encryption.
/// @return A tag as the output of the blinding cipher.
bignum ciphertext_blocks_to_tag(bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum authorized_data, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);

/// @brief Decrypt the tag by using the blinding cipher.
/// @param tag The created tag by the blinding cipher.
/// @param blinding_key A key for the blinding cipher. Must be the same as the key which was used for the tag creation.
/// @param blinding_nonce A nonce for the blinding cipher. Must be the same as the nonce which was used for the tag creation.
/// @return The input value for the blinding cipher to create the tag.
bignum decrypt_tag(bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);

/// @brief Calculates the syndrome (S). If everything is correct S equals 0 and otherwise it indicates an error with S = error * H^index_err
/// @param authorized_data Additional data which is not encrypted (max. 4 chunks).
/// @param ciphertext_blocks The ciphertext blocks with 4 chunks (128-bit) each and with a zero block at the end to calculate the number of blocks.
/// @param number_of_blocks The size of the ciphertext array.
/// @param hash_key A hash key determined by the function find_hash_key().
/// @param tag The created tag by the blinding cipher.
/// @param blinding_key A key for the blinding cipher. Must be different then the key for the plaintext encryption.
/// @param blinding_nonce A nonce for the blinding cipher. Must be different then the nonce for the plaintext encryption.
/// @return The syndrome (S).
bignum calculate_syndrome(bignum authorized_data, bignum ciphertext_blocks[], int number_of_blocks, bignum hash_key, bignum tag, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);

/// @brief Locates the corrupted block by using the syndrome values.
/// @param syndrome_values An array of syndrome values which gets calculated by "S_i = S * H^-i". If i == i_err -> S_i = error_vector.
/// @param number_of_blocks The number of syndrome values.
/// @param threshold The max. number of corrupted bits in a single block.
/// @return The index of the corrupted block or -1 if no corrupted block was found.
int locate_error(bignum syndrome_values[], int number_of_blocks, int threshold);

/// @brief Checks if the tag can be corrected.
/// @param corrupted_tag The corrupted tag.
/// @param new_tag The tag which is calculated by using the function "ciphertext_blocks_to_tag()".
/// @param threshold The max. number of corrupted bits in a single block.
/// @return True if the tag can be corrected and false if tag can't be corrected.
bool can_correct_parity(bignum corrupted_tag, bignum new_tag, int threshold);

/// @brief Tries to fix the corrupted block and returns the corrected version if it is possible.
/// @param authorized_data Additional data which is not encrypted (max. 4 chunks).
/// @param ciphertext_blocks The ciphertext blocks with 4 chunks (128-bit) each and with a zero block at the end to calculate the number of blocks.
/// @param number_of_blocks The size of the ciphertext array.
/// @param tag The created tag by the blinding cipher.
/// @param threshold The max. number of corrupted bits in a single block.
/// @param hash_key A hash key determined by the function find_hash_key().
/// @param blinding_key A key for the blinding cipher. Must be different then the key for the plaintext encryption.
/// @param blinding_nonce A nonce for the blinding cipher. Must be different then the nonce for the plaintext encryption.
/// @return True and empty strings when everything is correct. True and the corrected ciphertext/tag if the ciphertext/tag can be corrected. False and empty strings when the error is uncorrectable.
verify_result verify(bignum authorized_data, bignum ciphertext_blocks[], int number_of_blocks, bignum tag, int threshold, bignum hash_key, uint32_t blinding_key[8], uint32_t blinding_nonce[2]);

#endif
