// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   OpenOCD flash driver for the nafarr SpiXipController.                  *
 *                                                                         *
 *   The controller exposes a high-level command engine (not a raw SPI     *
 *   FIFO like the old VexRiscv SpiMasterCtrl): software loads an opcode    *
 *   plus flags, an address and a length, pushes the program payload into  *
 *   a TX FIFO, and writes the "start" register to launch the transfer.    *
 *   The engine itself issues the WREN prefix and the WIP status-poll, so   *
 *   the driver only has to wait for the "busy" bit to clear.              *
 *                                                                         *
 *   Flash reads use the controller's memory-mapped XIP window (bank->base).*
 *                                                                         *
 *   Register block (relative to the controller base passed to the         *
 *   "flash bank" command), after the 8-byte IpIdentification header:      *
 *     0x08 configure   (write: trigger EVCR config write -- unused here)   *
 *     0x0c config      (mode[7:0], dummyCycles[..8], evcr[23:16])          *
 *     0x10 command     (opcode[7:0], hasAddress[8], needsWren[9],          *
 *                       needsPoll[10])                                     *
 *     0x14 address     (24-bit flash address)                             *
 *     0x18 length      (9-bit data byte count)                            *
 *     0x1c start       (write: launch the command)                        *
 *     0x20 txData      (write: push one payload byte into the TX FIFO)     *
 *     0x24 status      (busy[0], statusReg[15:8], txAvailability[..16])    *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/time_support.h>
#include <helper/binarybuffer.h>
#include <target/target.h>
#include <target/algorithm.h>

/* Register offsets relative to the controller base (incl. 8-byte IP-ID hdr). */
#define NSX_REG_CONFIGURE	0x08
#define NSX_REG_CONFIG		0x0c
#define NSX_REG_COMMAND		0x10
#define NSX_REG_ADDRESS		0x14
#define NSX_REG_LENGTH		0x18
#define NSX_REG_START		0x1c
#define NSX_REG_TXDATA		0x20
#define NSX_REG_STATUS		0x24

/* command register bit fields */
#define NSX_CMD_HAS_ADDRESS	(1u << 8)
#define NSX_CMD_NEEDS_WREN	(1u << 9)
#define NSX_CMD_NEEDS_POLL	(1u << 10)

/* status register bit fields */
#define NSX_STATUS_BUSY		(1u << 0)
#define NSX_STATUS_TXAVAIL_SHIFT	16

/* SPI NOR opcodes used by the driver */
#define SPINOR_OP_PP		0x02	/* page program */
#define SPINOR_OP_SE_64K	0xd8	/* 64 KiB sector erase */

#define NSX_SECTOR_SIZE		(64 * 1024)
#define NSX_PAGE_SIZE		256
#define NSX_DEFAULT_TX_FIFO	64

/* timeouts (ms) */
#define NSX_TIMEOUT_PROG	1000
#define NSX_TIMEOUT_ERASE	5000

struct nafarr_spi_xip_flash_bank {
	bool probed;
	uint32_t ctrl_address;	/* controller register base in target memory map */
	unsigned int tx_fifo_depth;	/* max payload bytes per program command */
	/* XIP read-mode config word written to the `config` register before reads.
	 * Encodes mode/dummyCycles/evcr (e.g. 0x007f0702 = mode 0x02, dummy 7,
	 * evcr 0x7f). The booting firmware sets this up, but reset-halt clears it
	 * and a program/erase leaves the flash in single-SPI command mode -- so the
	 * driver re-arms it before every read. 0 = leave the controller as-is. */
	uint32_t xip_config;
	bool xip_config_set;
};

static int nsx_wr(struct flash_bank *bank, uint32_t reg, uint32_t value)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	return target_write_u32(bank->target, priv->ctrl_address + reg, value);
}

static int nsx_rd(struct flash_bank *bank, uint32_t reg, uint32_t *value)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	return target_read_u32(bank->target, priv->ctrl_address + reg, value);
}

/* Wait until the command engine clears its busy bit (covers WREN, the opcode,
 * the address/data phases and the internal WIP status-poll). */
static int nsx_wait_idle(struct flash_bank *bank, int timeout_ms)
{
	int64_t t0 = timeval_ms();

	for (;;) {
		uint32_t status;
		int retval = nsx_rd(bank, NSX_REG_STATUS, &status);
		if (retval != ERROR_OK)
			return retval;
		if (!(status & NSX_STATUS_BUSY))
			return ERROR_OK;
		if ((timeval_ms() - t0) > timeout_ms) {
			LOG_ERROR("nafarr_spi_xip: command engine busy timeout (status=0x%08" PRIx32 ")",
					status);
			return ERROR_FLASH_OPERATION_FAILED;
		}
		keep_alive();
	}
}

/* Re-arm the controller's XIP read mode (write `config`, trigger `configure`,
 * wait for the EVCR/mode write to the flash to finish). Needed before reading
 * through the XIP window after reset-halt or any command-engine operation,
 * which leave the flash in single-SPI command mode. */
static int nsx_apply_xip_config(struct flash_bank *bank)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	int retval;

	if (!priv->xip_config_set)
		return ERROR_OK;

	retval = nsx_wr(bank, NSX_REG_CONFIG, priv->xip_config);
	if (retval != ERROR_OK)
		return retval;
	retval = nsx_wr(bank, NSX_REG_CONFIGURE, 0);	/* trigger the EVCR/mode write */
	if (retval != ERROR_OK)
		return retval;
	return nsx_wait_idle(bank, NSX_TIMEOUT_PROG);
}

/* Issue one command engine transaction. payload/len may be NULL/0 (erase). */
static int nsx_command(struct flash_bank *bank, uint8_t opcode, bool has_address,
		uint32_t address, const uint8_t *payload, uint32_t len, int timeout_ms)
{
	int retval;
	uint32_t cmd = opcode | NSX_CMD_NEEDS_WREN | NSX_CMD_NEEDS_POLL;

	if (has_address)
		cmd |= NSX_CMD_HAS_ADDRESS;

	/* Push the payload into the TX FIFO before launching: the engine only
	 * starts draining it after WREN + opcode + address, so the whole chunk
	 * must already fit in the FIFO. Callers keep len <= tx_fifo_depth. */
	for (uint32_t i = 0; i < len; i++) {
		retval = nsx_wr(bank, NSX_REG_TXDATA, payload[i]);
		if (retval != ERROR_OK)
			return retval;
	}

	retval = nsx_wr(bank, NSX_REG_COMMAND, cmd);
	if (retval != ERROR_OK)
		return retval;
	retval = nsx_wr(bank, NSX_REG_ADDRESS, address & 0x00ffffff);
	if (retval != ERROR_OK)
		return retval;
	retval = nsx_wr(bank, NSX_REG_LENGTH, len);
	if (retval != ERROR_OK)
		return retval;

	/* launch */
	retval = nsx_wr(bank, NSX_REG_START, 1);
	if (retval != ERROR_OK)
		return retval;

	return nsx_wait_idle(bank, timeout_ms);
}

static int nafarr_spi_xip_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	for (unsigned int sector = first; sector <= last; sector++) {
		uint32_t addr = sector * NSX_SECTOR_SIZE;
		LOG_INFO("nafarr_spi_xip: erasing sector %u/%u (0x%08" PRIx32 ")",
				sector, last, addr);
		int retval = nsx_command(bank, SPINOR_OP_SE_64K, true, addr,
				NULL, 0, NSX_TIMEOUT_ERASE);
		if (retval != ERROR_OK) {
			LOG_ERROR("nafarr_spi_xip: erase of sector %u (0x%08" PRIx32 ") failed",
					sector, addr);
			return retval;
		}
		keep_alive();
	}

	return ERROR_OK;
}

/* Fallback: program byte-chunks directly via the registers over JTAG. Slow
 * (~1 KiB/s) but needs no work area. Used when the on-target loader can't run. */
static int nafarr_spi_xip_write_slow(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	uint32_t total = count, done = 0, next_report = 0;

	LOG_INFO("nafarr_spi_xip: programming 0x%" PRIx32 " bytes over JTAG (slow path)", count);

	while (count > 0) {
		/* Stay within one page and within the TX FIFO depth. */
		uint32_t page_room = NSX_PAGE_SIZE - (offset % NSX_PAGE_SIZE);
		uint32_t chunk = count;
		if (chunk > page_room)
			chunk = page_room;
		if (chunk > priv->tx_fifo_depth)
			chunk = priv->tx_fifo_depth;

		int retval = nsx_command(bank, SPINOR_OP_PP, true, offset,
				buffer, chunk, NSX_TIMEOUT_PROG);
		if (retval != ERROR_OK) {
			LOG_ERROR("nafarr_spi_xip: program at 0x%08" PRIx32 " failed", offset);
			return retval;
		}

		buffer += chunk;
		offset += chunk;
		count -= chunk;
		done += chunk;
		keep_alive();

		if (done >= next_report) {
			LOG_INFO("nafarr_spi_xip: programmed 0x%" PRIx32 "/0x%" PRIx32 " bytes (%" PRIu32 "%%)",
					done, total, (uint32_t)((uint64_t)done * 100 / total));
			next_report += 0x4000;
		}
	}

	return ERROR_OK;
}

/* RV32I target-resident loader, built from
 * contrib/loaders/flash/nafarr_spi_xip/. It drains a RAM buffer into the
 * controller's TX FIFO on the CPU, so the per-byte work stays off JTAG. */
static const uint8_t nafarr_spi_xip_riscv32_bin[] = {
#include "../../../contrib/loaders/flash/nafarr_spi_xip/nafarr_spi_xip.inc"
};

static int nafarr_spi_xip_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	struct target *target = bank->target;
	struct working_area *algo_wa = NULL, *data_wa = NULL;
	const unsigned int xlen = 32;	/* nafarr SpiXipController SoCs are RV32 */
	uint32_t data_wa_size = 0;
	int retval = ERROR_OK;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* Set up the on-target loader: bulk-copy each block to OCRAM, then let the
	 * CPU push it into the controller (~100x faster than per-byte JTAG). */
	if (target_alloc_working_area(target, sizeof(nafarr_spi_xip_riscv32_bin),
			&algo_wa) == ERROR_OK) {
		retval = target_write_buffer(target, algo_wa->address,
				sizeof(nafarr_spi_xip_riscv32_bin), nafarr_spi_xip_riscv32_bin);
		if (retval != ERROR_OK) {
			target_free_working_area(target, algo_wa);
			algo_wa = NULL;
		} else {
			/* Remaining work area is the data buffer (OCRAM can be as little
			 * as 8 KiB on small variants, so take whatever is left). */
			data_wa_size = MIN(target_get_working_area_avail(target), count);
			data_wa_size &= ~((uint32_t)NSX_PAGE_SIZE - 1);	/* whole pages only */
			if (data_wa_size < NSX_PAGE_SIZE ||
					target_alloc_working_area(target, data_wa_size, &data_wa) != ERROR_OK) {
				target_free_working_area(target, algo_wa);
				algo_wa = NULL;
			}
		}
	}

	if (!algo_wa) {
		LOG_WARNING("nafarr_spi_xip: no work area for the loader -- falling back");
		return nafarr_spi_xip_write_slow(bank, buffer, offset, count);
	}

	LOG_INFO("nafarr_spi_xip: programming 0x%" PRIx32 " bytes via on-target loader "
			"(%" PRIu32 " KiB buffer)", count, data_wa_size / 1024);

	struct reg_param reg_params[5];
	init_reg_param(&reg_params[0], "a0", xlen, PARAM_IN_OUT);	/* ctrl / result */
	init_reg_param(&reg_params[1], "a1", xlen, PARAM_OUT);		/* page_size */
	init_reg_param(&reg_params[2], "a2", xlen, PARAM_OUT);		/* buffer */
	init_reg_param(&reg_params[3], "a3", xlen, PARAM_OUT);		/* offset */
	init_reg_param(&reg_params[4], "a4", xlen, PARAM_OUT);		/* count */

	uint32_t total = count, done = 0, next_report = 0;
	while (count > 0) {
		uint32_t cur = MIN(count, data_wa_size);

		retval = target_write_buffer(target, data_wa->address, cur, buffer);
		if (retval != ERROR_OK)
			break;

		buf_set_u32(reg_params[0].value, 0, xlen, priv->ctrl_address);
		buf_set_u32(reg_params[1].value, 0, xlen, NSX_PAGE_SIZE);
		buf_set_u32(reg_params[2].value, 0, xlen, data_wa->address);
		buf_set_u32(reg_params[3].value, 0, xlen, offset);
		buf_set_u32(reg_params[4].value, 0, xlen, cur);

		retval = target_run_algorithm(target, 0, NULL,
				ARRAY_SIZE(reg_params), reg_params,
				algo_wa->address, 0, 10000, NULL);
		if (retval != ERROR_OK) {
			LOG_ERROR("nafarr_spi_xip: loader failed at offset 0x%08" PRIx32, offset);
			break;
		}
		if (buf_get_u32(reg_params[0].value, 0, xlen) != 0) {
			LOG_ERROR("nafarr_spi_xip: loader reported error at offset 0x%08" PRIx32, offset);
			retval = ERROR_FLASH_OPERATION_FAILED;
			break;
		}

		buffer += cur;
		offset += cur;
		count -= cur;
		done += cur;
		keep_alive();

		if (done >= next_report) {
			LOG_INFO("nafarr_spi_xip: programmed 0x%" PRIx32 "/0x%" PRIx32 " bytes (%" PRIu32 "%%)",
					done, total, (uint32_t)((uint64_t)done * 100 / total));
			next_report += 0x20000;
		}
	}

	for (unsigned int i = 0; i < ARRAY_SIZE(reg_params); i++)
		destroy_reg_param(&reg_params[i]);
	target_free_working_area(target, data_wa);
	target_free_working_area(target, algo_wa);
	return retval;
}

/* Reads come straight from the memory-mapped XIP window. The XIP read mode must
 * be (re-)armed first: reset-halt and command-engine ops leave the controller
 * in single-SPI command mode, which makes the window read back zeros. */
static int nafarr_spi_xip_read(struct flash_bank *bank, uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	int retval;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = nsx_apply_xip_config(bank);
	if (retval != ERROR_OK)
		return retval;

	return target_read_buffer(bank->target, bank->base + offset, count, buffer);
}

static int nafarr_spi_xip_probe(struct flash_bank *bank)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	uint32_t status;
	int retval;

	free(bank->sectors);
	bank->sectors = NULL;

	if (bank->size == 0) {
		LOG_ERROR("nafarr_spi_xip: flash size must be given in the 'flash bank' command");
		return ERROR_FLASH_BANK_INVALID;
	}

	/* Derive the usable TX FIFO depth from the idle txAvailability field so a
	 * program chunk never overflows the FIFO. Fall back to the default. */
	priv->tx_fifo_depth = NSX_DEFAULT_TX_FIFO;
	if (bank->target->state == TARGET_HALTED) {
		retval = nsx_rd(bank, NSX_REG_STATUS, &status);
		if (retval == ERROR_OK) {
			unsigned int avail = status >> NSX_STATUS_TXAVAIL_SHIFT;
			if (avail > 0 && avail <= NSX_PAGE_SIZE)
				priv->tx_fifo_depth = avail;
		}
	}

	bank->num_sectors = bank->size / NSX_SECTOR_SIZE;
	bank->sectors = alloc_block_array(0, NSX_SECTOR_SIZE, bank->num_sectors);
	if (!bank->sectors)
		return ERROR_FAIL;

	LOG_INFO("nafarr_spi_xip: %" PRIu32 " KiB flash, %u sectors of 64 KiB, ctrl @ 0x%08" PRIx32
			", TX FIFO %u bytes",
			bank->size / 1024, bank->num_sectors, priv->ctrl_address,
			priv->tx_fifo_depth);

	priv->probed = true;
	return ERROR_OK;
}

static int nafarr_spi_xip_auto_probe(struct flash_bank *bank)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	if (priv->probed)
		return ERROR_OK;
	return nafarr_spi_xip_probe(bank);
}

static int nafarr_spi_xip_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	struct nafarr_spi_xip_flash_bank *priv = bank->driver_priv;
	command_print_sameline(cmd, "nafarr SpiXipController at 0x%08" PRIx32, priv->ctrl_address);
	return ERROR_OK;
}

/* flash bank <name> nafarr_spi_xip <base> <size> <chip_width> <bus_width>
 *            <target> <ctrl_address> [<xip_config>] */
FLASH_BANK_COMMAND_HANDLER(nafarr_spi_xip_flash_bank_command)
{
	struct nafarr_spi_xip_flash_bank *priv;

	if (CMD_ARGC < 7)
		return ERROR_COMMAND_SYNTAX_ERROR;

	priv = malloc(sizeof(*priv));
	if (!priv)
		return ERROR_FAIL;

	priv->probed = false;
	priv->tx_fifo_depth = NSX_DEFAULT_TX_FIFO;
	priv->xip_config = 0;
	priv->xip_config_set = false;
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[6], priv->ctrl_address);

	/* Optional XIP read-mode config word (mode/dummyCycles/evcr), applied
	 * before every read. e.g. 0x007f0702. */
	if (CMD_ARGC >= 8) {
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], priv->xip_config);
		priv->xip_config_set = true;
	}

	bank->driver_priv = priv;
	return ERROR_OK;
}

/* nafarr_spi_xip xip_config <bank> <value> -- set and immediately apply the XIP
 * read-mode config word (lets you switch protocol, e.g. to Quad, at runtime). */
COMMAND_HANDLER(nafarr_spi_xip_handle_xip_config)
{
	struct flash_bank *bank;
	struct nafarr_spi_xip_flash_bank *priv;
	int retval;

	if (CMD_ARGC != 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;
	priv = bank->driver_priv;

	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], priv->xip_config);
	priv->xip_config_set = true;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}
	retval = nsx_apply_xip_config(bank);
	if (retval == ERROR_OK)
		command_print(CMD, "XIP read config set to 0x%08" PRIx32, priv->xip_config);
	return retval;
}

static const struct command_registration nafarr_spi_xip_exec_command_handlers[] = {
	{
		.name = "xip_config",
		.handler = nafarr_spi_xip_handle_xip_config,
		.mode = COMMAND_EXEC,
		.usage = "bank_id value",
		.help = "Set/apply the XIP read-mode config word (mode/dummyCycles/evcr), "
			"e.g. to switch the read protocol to Quad.",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration nafarr_spi_xip_command_handlers[] = {
	{
		.name = "nafarr_spi_xip",
		.mode = COMMAND_ANY,
		.help = "nafarr SpiXipController flash command group",
		.usage = "",
		.chain = nafarr_spi_xip_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver nafarr_spi_xip_flash = {
	.name = "nafarr_spi_xip",
	.usage = "flash bank <name> nafarr_spi_xip <base> <size> 0 0 <target> <ctrl_address> [<xip_config>]",
	.commands = nafarr_spi_xip_command_handlers,
	.flash_bank_command = nafarr_spi_xip_flash_bank_command,
	.erase = nafarr_spi_xip_erase,
	.write = nafarr_spi_xip_write,
	.read = nafarr_spi_xip_read,
	.probe = nafarr_spi_xip_probe,
	.auto_probe = nafarr_spi_xip_auto_probe,
	.erase_check = default_flash_blank_check,
	.info = nafarr_spi_xip_info,
	.free_driver_priv = default_flash_free_driver_priv,
};
