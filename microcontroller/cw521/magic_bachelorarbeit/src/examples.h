
/// @brief Runs the complete MAGIC mode with given threshold and [threshold] bit error in the first block.
/// @param text The text to be encrypted.
/// @param threshold The used threshold for MAGIC.
void magic_mode_complete(char *text, int threshold);

/// @brief Runs the complete Hamming Code per block with one bit error in the first block.
/// @param text The text to be encrypted.
void hamming_code_per_block_complete(char *text);

/// @brief Runs the complete Hamming Code over all blocks with one bit error in the first block.
/// @param text The text to be encrypted.
void hamming_code_all_blocks_complete(char *text);
