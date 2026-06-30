// SPDX-License-Identifier: GPL-2.0-or-later

/* Target-resident write loader for the nafarr SpiXipController.
 *
 * Runs on the RISC-V core during programming: drains a RAM buffer (filled in
 * bulk by OpenOCD) into the controller's TX FIFO and issues page-program
 * commands, so the slow per-byte work happens on the CPU instead of over JTAG.
 *
 * Built for plain RV32I (no M/A/C) -- avoid multiply/divide; page_size is a
 * power of two so masks replace the modulus.
 *
 * Entry (riscv_wrapper.S) calls:
 *   flash_nafarr_spi_xip(a0=ctrl_base, a1=page_size, a2=buffer, a3=offset,
 *                        a4=count) -> a0 = 0 on success
 */

#include <stdint.h>

/* Register offsets (relative to the controller base). */
#define NSX_REG_COMMAND		0x10
#define NSX_REG_ADDRESS		0x14
#define NSX_REG_LENGTH		0x18
#define NSX_REG_START		0x1c
#define NSX_REG_TXDATA		0x20
#define NSX_REG_STATUS		0x24

#define NSX_OP_PP		0x02
#define NSX_CMD_HAS_ADDRESS	(1u << 8)
#define NSX_CMD_NEEDS_WREN	(1u << 9)
#define NSX_CMD_NEEDS_POLL	(1u << 10)
#define NSX_STATUS_BUSY		(1u << 0)

#define NSX_TX_FIFO_DEPTH	64

static inline uint32_t rd(volatile uint8_t *base, uint32_t off)
{
	return *(volatile uint32_t *)(base + off);
}

static inline void wr(volatile uint8_t *base, uint32_t off, uint32_t val)
{
	*(volatile uint32_t *)(base + off) = val;
}

int flash_nafarr_spi_xip(volatile uint8_t *ctrl, uint32_t page_size,
		const uint8_t *buffer, uint32_t offset, uint32_t count)
{
	while (count > 0) {
		uint32_t page_room = page_size - (offset & (page_size - 1));
		uint32_t chunk = count;

		if (chunk > page_room)
			chunk = page_room;
		if (chunk > NSX_TX_FIFO_DEPTH)
			chunk = NSX_TX_FIFO_DEPTH;

		for (uint32_t i = 0; i < chunk; i++)
			wr(ctrl, NSX_REG_TXDATA, buffer[i]);

		wr(ctrl, NSX_REG_COMMAND, NSX_OP_PP | NSX_CMD_HAS_ADDRESS |
				NSX_CMD_NEEDS_WREN | NSX_CMD_NEEDS_POLL);
		wr(ctrl, NSX_REG_ADDRESS, offset & 0x00ffffff);
		wr(ctrl, NSX_REG_LENGTH, chunk);
		wr(ctrl, NSX_REG_START, 1);

		/* busy takes a couple of cycles to assert after START; at CPU speed we
		 * must wait for it to go high before waiting for it to clear, otherwise
		 * we race ahead and push the next chunk into a still-busy engine. A
		 * page-program holds busy high for milliseconds, so it can't be missed. */
		while (!(rd(ctrl, NSX_REG_STATUS) & NSX_STATUS_BUSY))
			;
		while (rd(ctrl, NSX_REG_STATUS) & NSX_STATUS_BUSY)
			;

		buffer += chunk;
		offset += chunk;
		count -= chunk;
	}

	return 0;
}
