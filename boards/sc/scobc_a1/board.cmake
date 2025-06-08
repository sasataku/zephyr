# SPDX-License-Identifier: Apache-2.0

if("${SCOBC_A1_USE_FTDI}" STREQUAL "y")
	set(SCOBC_A1_CFG "openocd-ftdi.cfg")
else()
	set(SCOBC_A1_CFG "openocd.cfg")
endif()

if("${SCOBC_A1_FLASH_RAM}" STREQUAL "y")
	board_runner_args(openocd
		"--use-elf"
		"--config=${BOARD_DIR}/support/${SCOBC_A1_CFG}")
else()
	board_runner_args(openocd
		"--cmd-pre-init=flash bank sc_flash scqspi 0x0000000 0 0 0 cortex_m3.cpu 0x01A00000 0"
		"--config=${BOARD_DIR}/support/${SCOBC_A1_CFG}")
endif()

include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)
