/*
 Copyright (C) 2018 NewAE Technology Inc. All Rights Reserved.

  This file is part of the CW522 Ballistic Gel Project.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.


 */

#include <asf.h>
#include "conf_usb.h"
#include "stdio_serial.h"
#include "ui.h"
#include "genclk.h"
#include "tasks.h"
#include "usb.h"
#include "sysclk.h"
#include "naeusb/naeusb_default.h"
#include "naeusb/naeusb.h"
#include "naeusb_ballistic.h"
#include "naeusb/usb_xmem.h"
#include <string.h>

// ------------------------------------- my code start --------------------------------------------------------------------

#include "magic_bachelorarbeit/src/galois.h"
#include "magic_bachelorarbeit/src/util_functions.h"
#include "magic_bachelorarbeit/src/bignum.h"
#include "magic_bachelorarbeit/src/salsa20.h"
#include "magic_bachelorarbeit/src/magic_mode.h"
#include "magic_bachelorarbeit/src/hamming_code.h"

#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"


// the register names for counting cycles
volatile uint32_t *DWT_CYCCNT;
volatile uint32_t *DWT_CONTROL;
volatile uint32_t *SCB_DEMCR;


void reset_timer() {
    DWT_CYCCNT   = (volatile uint32_t *)0xE0001004; // address of the register
    DWT_CONTROL  = (volatile uint32_t *)0xE0001000; // address of the register
    SCB_DEMCR    = (volatile uint32_t *)0xE000EDFC; // address of the register
    *SCB_DEMCR   = *SCB_DEMCR | 0x01000000;
    *DWT_CONTROL = 0;
    *DWT_CYCCNT  = 0; // reset the counter
}


void start_timer() {
    *DWT_CONTROL = *DWT_CONTROL | 1 ; // enable the counter
}


void stop_timer() {
    *DWT_CONTROL = *DWT_CONTROL | 0 ; // disable the counter
}


uint32_t get_cycles() {
  return *DWT_CYCCNT;
}


void encryption_changing_blocks(int start, int end, int interval, int number_of_measurements) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // 16 chars (ASCII) -> one block
  char *one_block_text = "1234ABCD5678EFGH";

  // iterate over blocks
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      bignum blocks[i];
      int space_for_text = i * 16;
      char text[space_for_text];

      // fill the string
      for (int k = 0; k < i; k++) {
        if (k == 0) {
          strcpy(text, one_block_text);
        }
        else {
          strcat(text, one_block_text);
        }
      }

      reset_timer();
      start_timer();

      // encryption
      plaintext_to_ciphertext_blocks(blocks, text, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void decryption_changing_blocks(int start, int end, int interval, int number_of_measurements) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // iterate over blocks
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      // fill the blocks
      bignum blocks[i];
      for (int k = 0; k < i; k++) {
        blocks[k] = init_bignum(one_block);
      }

      int number_of_chars = calculate_number_of_chars_from_bignum_array(blocks, i);
      char text[number_of_chars];

      reset_timer();
      start_timer();

      // decryption
      ciphertext_blocks_to_plaintext_as_str(text, blocks, i, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void tag_generation_given_blocks_changing_blocks(int start, int end, int interval, int number_of_measurements) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // iterate over blocks
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      // fill the blocks
      bignum blocks[i];
      for (int k = 0; k < i; k++) {
        blocks[k] = init_bignum(one_block);
      }

      // dummy hash_key
      bignum hash_key = init_bignum_to_one();

      reset_timer();
      start_timer();

      // tag generation
      volatile bignum tag = ciphertext_blocks_to_tag(blocks, i, blocks[0], hash_key, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void find_hash_key_changing_blocks(int start, int end, int interval, int number_of_measurements, int threshold) {
  // statement to set a breakpoint for printing
  volatile int PRINT_VALUES = 42;

  // iterate over blocks
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      reset_timer();
      start_timer();

      // calculate hash_key
      volatile bignum hash_key = find_hash_key_value(threshold, i, 1, 42);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      // checks if a hash_key was found
      volatile bool hash_key_found = true;
      if (!is_bignum_not_zero(hash_key)) {
        hash_key_found = false;
      }

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void find_hash_key_changing_threshold(int start, int end, int interval, int number_of_measurements, int number_of_blocks) {
  // statement to set a breakpoint for printing
  volatile int PRINT_VALUES = 42;

  // iterate over thresholds
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      reset_timer();
      start_timer();

      // calculate hash_key
      volatile bignum hash_key = find_hash_key_value(i, number_of_blocks, 1, 42);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      // checks if a hash_key was found
      volatile bool hash_key_found = true;
      if (!is_bignum_not_zero(hash_key)) {
        hash_key_found = false;
      }

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


// to get an uncorrectable error at least two blocks are required and parameter error_in_ciphertext must be true
void verify_changing_blocks(int start, int end, int interval, int number_of_measurements, int threshold, bool error_in_ciphertext, bool error_in_tag, bool uncorrectable_error) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // values for dummy hash_key
  uint32_t hash_hex[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

  // iterate over blocks
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      // fill the blocks
      bignum blocks[i];
      for (int k = 0; k < i; k++) {
        blocks[k] = init_bignum(one_block);
      }

      // calculate necessary parameters
      bignum authorized_data = init_bignum_to_zero();
      bignum hash_key = init_bignum(hash_hex); // dummy hash_key
      bignum tag = ciphertext_blocks_to_tag(blocks, i, hash_key, authorized_data, key, nonce);

      // set errors in ciphertext blocks and tag
      for (int k = 0; k < threshold; k++) {
        if (error_in_ciphertext) {
          blocks[0] = one_bit_modification(blocks[0], k);
        }
        if (error_in_tag) {
          tag = one_bit_modification(tag, k);
        }
        // at least two blocks are required and parameter error_in_ciphertext must be true to get an uncorrectable error
        if (uncorrectable_error) {
          blocks[1] = one_bit_modification(blocks[1], k);
        }
      }

      reset_timer();
      start_timer();

      // verify ciphertext blocks
      volatile verify_result res = verify(authorized_data, blocks, i, tag, threshold, hash_key, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


// to get an uncorrectable error at least two blocks are required and parameter error_in_ciphertext must be true
void verify_changing_threshold(int start, int end, int interval, int number_of_measurements, int number_of_blocks, bool error_in_ciphertext, bool error_in_tag, bool uncorrectable_error) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // values for dummy hash_key
  uint32_t hash_hex[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

  // iterate over thresholds
  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      // fill the blocks
      bignum blocks[number_of_blocks];
      for (int k = 0; k < number_of_blocks; k++) {
        blocks[k] = init_bignum(one_block);
      }

      // calculate necessary parameters
      bignum authorized_data = init_bignum_to_zero();
      bignum hash_key = init_bignum(hash_hex); // dummy hash_key
      bignum tag = ciphertext_blocks_to_tag(blocks, number_of_blocks, hash_key, authorized_data, key, nonce);

      // set errors in ciphertext blocks and tag
      for (int k = 0; k < i; k++) {
        if (error_in_ciphertext) {
          blocks[0] = one_bit_modification(blocks[0], k);
        }
        if (error_in_tag) {
          tag = one_bit_modification(tag, k);
        }
        // at least two blocks are required and parameter error_in_ciphertext must be true to get an uncorrectable error
        if (uncorrectable_error) {
          blocks[1] = one_bit_modification(blocks[1], k);
        }
      }

      reset_timer();
      start_timer();

      // verify ciphertext blocks
      volatile verify_result res = verify(authorized_data, blocks, number_of_blocks, tag, i, hash_key, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void verify_changing_faulty_block(int start_block_index, int end_block_index, int interval, int number_of_measurements, int number_of_blocks, int threshold, bool uncorrectable_error) {
  uint32_t key[8] = {
    0xEAEBECED, 0xEEEFF0F1, 0xF2F3F4F5, 0xF6F7F8F9,
    0xFAFBFCFD, 0xFEFF0001, 0x02030405, 0x06070809
  };
  uint32_t nonce[2] = {0x0, 0x0};

  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // values for dummy hash_key
  uint32_t hash_hex[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};

  // iterate over block indices
  for (int i = start_block_index; i <= end_block_index; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      // fill the blocks
      bignum blocks[number_of_blocks];
      for (int k = 0; k < number_of_blocks; k++) {
        blocks[k] = init_bignum(one_block);
      }

      // calculate necessary parameters
      bignum authorized_data = init_bignum_to_zero();
      bignum hash_key = init_bignum(hash_hex); // dummy hash_key
      bignum tag = ciphertext_blocks_to_tag(blocks, number_of_blocks, hash_key, authorized_data, key, nonce);

      // error(s) in ciphertext block(s)
      blocks[i] = one_bit_modification(blocks[i], 42);
      if (uncorrectable_error) {
        blocks[0] = one_bit_modification(blocks[0], 33);
      }

      reset_timer();
      start_timer();

      // verify ciphertext blocks
      volatile verify_result res = verify(authorized_data, blocks, number_of_blocks, tag, threshold, hash_key, key, nonce);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}


void hc_add_parity_per_block(int start, int end, int interval, int number_of_measurements) {
  // this respresents one ciphertext block
  uint32_t one_block[4] = {0x12345678, 0xabcdef90, 0x87654321, 0x09fedcba};

  // 16 chars (ASCII) -> one block
  char *one_block_text = "1234ABCD5678EFGH";

  // iterate over blocks
  for (volatile int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements]; // all cycle counts are saved here to calculate the avarage and standard deviation
    // measure the cycle count [number_of_measurements] times
    for (int f = 0; f < number_of_measurements; f++) {
      bignum blocks[i];
      int space_for_text = i * 16;
      char text[space_for_text];

      // fill the blocks and text
      for (int k = 0; k < i; k++) {
        blocks[k] = init_bignum(one_block);
        if (k == 0) {
          strcpy(text, one_block_text);
        }
        else {
          strcat(text, one_block_text);
        }
      }

      int number_of_bignums_parity = number_of_encrypted_ciphertext_blocks_with_parity_from_string(text);

      reset_timer();
      start_timer();

      volatile bignum blocks_parity[number_of_bignums_parity];
      add_parity_to_bignum_array(blocks_parity, blocks, i, number_of_bignums_parity);

      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();

      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float sd = standard_deviation(results, number_of_measurements, avg);

    // statement to set a breakpoint for printing
    volatile int PRINT_VALUES = avg;
  }
}

// ------------------------------------------- my code end -----------------------------------------------------------------

//Serial Number - will be read by device ID
char usb_serial_number[33] = "000000000000DEADBEEF";

static void configure_console(void);

/*! \brief Main function. Execution starts here.
 */
int main(void)
{
  uint32_t serial_number[4];

  // Read Device-ID from SAM3U. Do this before enabling interrupts etc.
  flash_read_unique_id(serial_number, sizeof(serial_number));

  configure_console();

  irq_initialize_vectors();
  cpu_irq_enable();

  // Initialize the sleep manager
  sleepmgr_init();
#if !SAMD21 && !SAMR21
  sysclk_init();
  board_init();
#else
  system_init();
#endif

  //Convert serial number to ASCII for USB Serial number
  for(unsigned int i = 0; i < 4; i++){
    sprintf(usb_serial_number+(i*8), "%08x", (unsigned int)serial_number[i]);
  }
  usb_serial_number[32] = 0;

  printf("ChipSHOUTER C521 Ballistic Gel Online. Firmware build: %s/%s\n", __TIME__, __DATE__);
  printf("Serial number: %s\n", usb_serial_number);


  /* Enable SMC */
  pmc_enable_periph_clk(ID_SMC);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D0, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D1, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D2, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D3, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D4, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D5, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D6, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D7, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D8, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D9, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D10, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D11, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D12, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D13, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D14, PIN_EBI_DATA_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_DATA_BUS_D15, PIN_EBI_DATA_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_NRD, PIN_EBI_NRD_FLAGS);
  gpio_configure_pin(PIN_EBI_NWE, PIN_EBI_NWE_FLAGS);
  gpio_configure_pin(PIN_EBI_NCS0, PIN_EBI_NCS0_FLAGS);

  gpio_configure_pin(PIN_EBI_ADDR_BUS_NBS0, PIN_EBI_ADDR_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_NBS1, PIN_EBI_ADDR_BUS_FLAG2);

  gpio_configure_pin(PIN_EBI_ADDR_BUS_A1, PIN_EBI_ADDR_BUS_FLAG1);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A2, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A3, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A4, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A5, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A6, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A7, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A8, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A9, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A10, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A11, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A12, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A13, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A14, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A15, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A16, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A17, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A18, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A19, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A20, PIN_EBI_ADDR_BUS_FLAG2);
  gpio_configure_pin(PIN_EBI_ADDR_BUS_A21, PIN_EBI_ADDR_BUS_FLAG2);

  /* Configure EBI I/O for PSRAM connection */
  printf("Setting up SRAM Communication\n");

  /* complete SMC configuration between PSRAM and SMC waveforms. */
  /*
  smc_set_setup_timing(SMC, 0, SMC_SETUP_NWE_SETUP(0)
  | SMC_SETUP_NCS_WR_SETUP(2)
  | SMC_SETUP_NRD_SETUP(2)
  | SMC_SETUP_NCS_RD_SETUP(2));
  smc_set_pulse_timing(SMC, 0, SMC_PULSE_NWE_PULSE(6)
  | SMC_PULSE_NCS_WR_PULSE(6)
  | SMC_PULSE_NRD_PULSE(6)
  | SMC_PULSE_NCS_RD_PULSE(6));
  smc_set_cycle_timing(SMC, 0, SMC_CYCLE_NWE_CYCLE(8)
  | SMC_CYCLE_NRD_CYCLE(8));
  smc_set_mode(SMC, 0, SMC_MODE_READ_MODE_NRD_CTRL | SMC_MODE_WRITE_MODE_NWE_CTRL
  | SMC_MODE_DBW_BIT_16);
  */

    smc_set_setup_timing(SMC, 0, SMC_SETUP_NWE_SETUP(0)
    | SMC_SETUP_NCS_WR_SETUP(4)
    | SMC_SETUP_NRD_SETUP(4)
    | SMC_SETUP_NCS_RD_SETUP(4));
    smc_set_pulse_timing(SMC, 0, SMC_PULSE_NWE_PULSE(12)
    | SMC_PULSE_NCS_WR_PULSE(12)
    | SMC_PULSE_NRD_PULSE(12)
    | SMC_PULSE_NCS_RD_PULSE(12));
    smc_set_cycle_timing(SMC, 0, SMC_CYCLE_NWE_CYCLE(16)
    | SMC_CYCLE_NRD_CYCLE(16));
    smc_set_mode(SMC, 0, SMC_MODE_READ_MODE_NRD_CTRL | SMC_MODE_WRITE_MODE_NWE_CTRL
    | SMC_MODE_DBW_BIT_16);

  /*
  osc_enable(OSC_MAINCK_XTAL);
      osc_wait_ready(OSC_MAINCK_XTAL);
      pmc_switch_mck_to_mainck(CONFIG_SYSCLK_PRES);
  */
  ui_init();

  // Start USB stack to authorize VBus monitoring
  udc_start();

  printf("Event Loop Entered, waiting...\n");

  // The main loop manages only the power mode
  // because the USB management is done by interrupt
	naeusb_register_handlers();
  ballistic_register_handlers();

  // ------------------------------------- my code start ---------------------------------------------------------------------

  // encryption_changing_blocks(50, 250, 25, 1);
  // decryption_changing_blocks(1, 10, 1, 10);
  // tag_generation_given_blocks_changing_blocks(1, 10, 1, 10);
  // find_hash_key_changing_blocks(1, 3, 1, 10, 1);
  // find_hash_key_changing_threshold(1, 2, 1, 5, 2);
  // verify_changing_blocks(1, 5, 1, 5, 1, false, false, false);
  // verify_changing_threshold(1, 5, 1, 5, 1, false, false, false);
  // verify_changing_faulty_block(0, 2, 1, 5, 3, 1, false);

  hc_add_parity_per_block(150, 250, 25, 1);

  // --------------------------------------- my code end -------------------------------------------------------------------------------------------

  while (true) {
    // sleepmgr_enter_sleep();
  }
}

/**
 *  Configure UART console.
 */
static void configure_console(void)
{
  const usart_serial_options_t uart_serial_options = {
    .baudrate = CONF_UART_BAUDRATE,
    .paritytype = CONF_UART_PARITY
  };

  /* Configure console UART. */
  sysclk_enable_peripheral_clock(CONSOLE_UART_ID);
  stdio_serial_init(CONF_UART, &uart_serial_options);
}
