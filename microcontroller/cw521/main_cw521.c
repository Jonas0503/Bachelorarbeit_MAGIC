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
    DWT_CYCCNT   = (uint32_t *)0xE0001004; // address of the register
    DWT_CONTROL  = (uint32_t *)0xE0001000; // address of the register
    SCB_DEMCR    = (uint32_t *)0xE000EDFC; // address of the register
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

  char *one_block_text = "1234ABCD5678EFGH";

  for (int i = start; i <= end; i += interval) {
    volatile uint32_t results[number_of_measurements];
    for (int f = 0; f < number_of_measurements; f++) {
      bignum blocks[i];
      int space_for_text = i * 16;
      char text[space_for_text];

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
      plaintext_to_ciphertext_blocks(blocks, text, key, nonce);
      volatile uint32_t number_of_cycles = get_cycles();
      stop_timer();
      volatile int x = 42;
      results[f] = number_of_cycles;
    }

    volatile float avg = average(results, number_of_measurements);
    volatile float vari = standard_deviation(results, number_of_measurements, avg);

    volatile int y = 42;
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

  encryption_changing_blocks(1, 10, 1, 30);

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
