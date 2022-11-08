// SPDX-License-Identifier: GPL-2.0-or-later
/***************************************************************************
 *	 Copyright (C) 2020 Jean THOMAS
 *	 pub0@git.jeanthomas.me
 *	 Copyright (C) 2022 Patrick Dussud
 *	 phdussud@hotmail.com
 ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* project specific includes */
#include <helper/bits.h>
#include <helper/time_support.h>
#include <jtag/jtag.h>
#include <jtag/commands.h>
#include <jtag/interface.h>


#include "bitq.h"
#include "libusb_helper.h"

/**
 *
 * CMD_STOP terminates the stream of commands contained in current the USB packet
 *
 * CMD_INFO returns a uint8_t[10] to the host software. This
 * could be used to check DirtyJTAG firmware version
 * or supported commands.
 *
 * CMD_FREQ sets the clock frequency on the probe.
 * payload[0] << 8 + payload[1] is the desired freq in khz
 *
 * CMD_XFER writes data on TDI, reads TDO unless NO_READ modifier is used.
 * payload[0] is the length of the tdi stream in bits. EXTEND_LENGTH adds 256 to
 * the length. Effective max bit length is 62*8
 * payload[1....] is the stream of tdi bits
 * This also sets TMS to low.
 *
 * CMD_SETSIG set the output TCK, TDI, TMS, SRST, TSRST.
 * payload[0] is a mask of what to set according to SignalIdentifier
 * payload[1] is the signals values according to SignalIdentifier
 *
 * CMD_GETSIG gets the current signal state of TDO
 *
 * CMD_CLK sends clock pulses with specific TMS and TDI state.
 * if READOUT is added to the command, it will read TDO during the last clock
 * pulse
 * payload[0] signals, payload[1] number of clock pulses
 */

enum dirtyjtag_cmd {
	CMD_STOP = 0x00,
	CMD_INFO = 0x01,
	CMD_FREQ = 0x02,
	CMD_XFER = 0x03,
	CMD_SETSIG = 0x04,
	CMD_GETSIG = 0x05,
	CMD_CLK = 0x06
};

/* Modifiers applicable only to DirtyJTAG2 */
enum command_modifier {
	EXTEND_LENGTH = 0x40,
	NO_READ = 0x80,
	READOUT = 0x80
};
struct version_specific {
	uint8_t no_read;	/* command modifier for xfer no read */
	uint16_t max_bits;	/* max bit count that can be transferred */
};

static struct version_specific dirtyjtag_v_options[3] = {
	{0, 240},
	{0, 240},
	{NO_READ, 496}
};
static int dirtyjtag_version;
enum dirtyjtag_signal {
	SIG_TCK = BIT(1),
	SIG_TDI = BIT(2),
	SIG_TDO = BIT(3),
	SIG_TMS = BIT(4),
	SIG_TRST = BIT(5),
	SIG_SRST = BIT(6)
};

enum out_state {
	OUTSTATE_CLK = 0,
	OUTSTATE_XFER,
};

/**
 * USB settings
 */
static unsigned int dirtyjtag_ep_write = 0x01;
static unsigned int dirtyjtag_ep_read = 0x82;
#define DIRTYJTAG_USB_TIMEOUT 100
static const uint16_t dirtyjtag_vid = 0x1209;
static const uint16_t dirtyjtag_pid = 0xC0CA;
static struct libusb_device_handle *usb_handle;

/*
 * DirtyJTAG command buffer code
 */
#define DIRTYJTAG_BUFFER_SIZE 64
static const size_t dirtyjtag_buffer_size = DIRTYJTAG_BUFFER_SIZE;
static uint8_t dirtyjtag_buffer[DIRTYJTAG_BUFFER_SIZE];
static size_t dirtyjtag_buffer_use;

struct dirtyjtag_bitq_state {
	uint32_t tdi_out_count;
	uint32_t max_tdi_count;
	uint32_t tdo_in_expected;
	int tdo_bytes_expected;
	bool prev_tms;
	int out_state;
	uint8_t *current_command_array;
	uint16_t in_bit_counts[1 + DIRTYJTAG_BUFFER_SIZE / 3];
	uint32_t expected_in_command_count;
	uint32_t in_command_count;
	uint8_t in_buffer[2 * DIRTYJTAG_BUFFER_SIZE];
	uint32_t in_buffer_fill;
	uint32_t in_command_idx;
	uint32_t in_bit_idx;
	uint8_t out_buffer[DIRTYJTAG_BUFFER_SIZE];
	uint8_t out_command_count; /* command count for the current command array */
};

static struct dirtyjtag_bitq_state s_dirtyjtag_bitq;
static struct dirtyjtag_bitq_state *djtg_bitq = &s_dirtyjtag_bitq;
static struct bitq_interface dirtyjtag_bitq_interface;

static int dirtyjtag_buffer_flush(void)
{
	size_t sent = 0;

	if (dirtyjtag_buffer_use == 0)
		return ERROR_OK;

	dirtyjtag_buffer[dirtyjtag_buffer_use] = CMD_STOP;

	int res =
		jtag_libusb_bulk_write(usb_handle, dirtyjtag_ep_write, (char *)dirtyjtag_buffer,
							   dirtyjtag_buffer_use + 1, DIRTYJTAG_USB_TIMEOUT, (int *)&sent);
	if (res != ERROR_OK)
		return res;
	if (sent != dirtyjtag_buffer_use + 1) {
		LOG_ERROR("error writing to device");
		return ERROR_JTAG_DEVICE_ERROR;
	}
	dirtyjtag_buffer_use = 0;
	return ERROR_OK;
}

static int dirtyjtag_buffer_append(const uint8_t *command, size_t length)
{
	if ((dirtyjtag_buffer_use + length + 1) > dirtyjtag_buffer_size) {
		int res = dirtyjtag_buffer_flush();
		if (res != ERROR_OK)
			return res;
	}
	memcpy(&dirtyjtag_buffer[dirtyjtag_buffer_use], command, length);
	dirtyjtag_buffer_use += length;
	return ERROR_OK;
}

#define buffer_pos_of_bit(n) (2 + ((n) / 8))

/* send to the probe and get an answer back if tdo_bytes_expected is > 0 */
static int dirtyjtag_flush_bitq(void)
{
	int out_len = djtg_bitq->current_command_array - djtg_bitq->out_buffer;
	if (out_len == 0)
		return ERROR_OK;
	if (out_len < DIRTYJTAG_BUFFER_SIZE) {
		djtg_bitq->out_buffer[out_len] = CMD_STOP;
		out_len++;
	}
	LOG_DEBUG_IO("sending %d bytes to dirtyjtag probe", out_len);
	int sent;
	int res =
		jtag_libusb_bulk_write(usb_handle, dirtyjtag_ep_write, (char *)djtg_bitq->out_buffer,
							   out_len, DIRTYJTAG_USB_TIMEOUT, (int *)&sent);
	if (res != ERROR_OK)
		return res;
	if (sent != out_len) {
		LOG_ERROR("error writing to device");
		return ERROR_JTAG_DEVICE_ERROR;
	}
	if (djtg_bitq->tdo_bytes_expected > 0) {
		int read;
		res = jtag_libusb_bulk_read(usb_handle, dirtyjtag_ep_read,
									(char *)djtg_bitq->in_buffer + djtg_bitq->in_buffer_fill,
									64, DIRTYJTAG_USB_TIMEOUT, &read);
		if (res != ERROR_OK)
			return res;
		if (read != djtg_bitq->tdo_bytes_expected) {
			LOG_ERROR("error reading device: amount read incorrect");
			return ERROR_JTAG_DEVICE_ERROR;
		}
		djtg_bitq->in_buffer_fill += djtg_bitq->tdo_bytes_expected;
		djtg_bitq->in_command_count = djtg_bitq->expected_in_command_count;
		djtg_bitq->tdo_bytes_expected = 0;
	}
	/* re-init all relevant state variables */
	memset(djtg_bitq->out_buffer, 0, DIRTYJTAG_BUFFER_SIZE);
	djtg_bitq->current_command_array = djtg_bitq->out_buffer;
	djtg_bitq->out_command_count = 0;
	return ERROR_OK;
}
static int dirtyjtag_open_command(int state)
{
	if (state == OUTSTATE_CLK)
		djtg_bitq->current_command_array[0] = CMD_CLK;
	else
		djtg_bitq->current_command_array[0] = CMD_XFER;
	djtg_bitq->max_tdi_count = MIN(dirtyjtag_v_options[dirtyjtag_version].max_bits,
								   8 * (djtg_bitq->out_buffer + (DIRTYJTAG_BUFFER_SIZE - 2) -
										djtg_bitq->current_command_array));
	djtg_bitq->current_command_array[1] = 0;
	djtg_bitq->current_command_array[2] = 0;
	return 0;
}

static int dirtyjtag_close_command(bool force_send_to_probe)
{
	if ((djtg_bitq->current_command_array[0] & 0xF) == CMD_XFER) {
		/* skip close if the command is not initialized */
		/* this can happen right after init or flush */
		if (djtg_bitq->tdi_out_count != 0) {
			if (djtg_bitq->tdi_out_count > 255) {
				djtg_bitq->current_command_array[0] |= EXTEND_LENGTH;
				djtg_bitq->current_command_array[1] = djtg_bitq->tdi_out_count - 256;
			} else {
				djtg_bitq->current_command_array[1] = djtg_bitq->tdi_out_count;
			}
			if (djtg_bitq->tdo_in_expected == 0)
				djtg_bitq->current_command_array[0] |= NO_READ;
			djtg_bitq->current_command_array += 2 + ((djtg_bitq->tdi_out_count + 7) / 8);
			djtg_bitq->out_command_count++;
		}
	} else if ((djtg_bitq->current_command_array[0] & 0xF) == CMD_CLK) {
		/* skip close if the command is not initialized */
		/* this can happen right after init or flush */
		if (djtg_bitq->current_command_array[2] != 0) {
			if (djtg_bitq->tdo_in_expected != 0)
				djtg_bitq->current_command_array[0] |= READOUT;
			djtg_bitq->current_command_array += 3;
			djtg_bitq->out_command_count++;
		}
	}
	djtg_bitq->tdi_out_count = 0;
	if (djtg_bitq->tdo_in_expected != 0) {
		uint32_t prev_bytes = djtg_bitq->tdo_bytes_expected;
		djtg_bitq->tdo_bytes_expected += (djtg_bitq->tdo_in_expected + 7) / 8;
		djtg_bitq->in_bit_counts[djtg_bitq->expected_in_command_count] =
			prev_bytes * 8 + djtg_bitq->tdo_in_expected;
		djtg_bitq->expected_in_command_count++;
		djtg_bitq->tdo_in_expected = 0;
	}
	if (force_send_to_probe || (djtg_bitq->out_buffer + (DIRTYJTAG_BUFFER_SIZE - 3) <
								djtg_bitq->current_command_array)) {
		int res = dirtyjtag_flush_bitq();
		if (res != ERROR_OK)
			return res;
	}
	return 0;
}

static int dirtyjtag_init_bitq(void)
{
	bitq_interface = &dirtyjtag_bitq_interface;
	memset(djtg_bitq, 0, sizeof(*djtg_bitq));
	djtg_bitq->current_command_array = djtg_bitq->out_buffer;
	dirtyjtag_open_command(djtg_bitq->out_state);
	return 0;
}

static int dirtyjtag_getversion(void)
{
	int actual_length;
	uint8_t buf[] = {CMD_INFO, CMD_STOP};
	uint8_t rx_buf[64];
	int res = jtag_libusb_bulk_write(usb_handle, dirtyjtag_ep_write, (char *)buf, 2,
									 DIRTYJTAG_USB_TIMEOUT, &actual_length);
	if (res != ERROR_OK) {
		LOG_ERROR("%s: usb bulk write failed", __func__);
		return ERROR_JTAG_INIT_FAILED;
	}
	do {
		res = jtag_libusb_bulk_read(usb_handle, dirtyjtag_ep_read, (char *)rx_buf, 64,
									DIRTYJTAG_USB_TIMEOUT, &actual_length);
		if (res) {
			LOG_ERROR("%s: usb bulk read failed", __func__);
			return ERROR_JTAG_INIT_FAILED;
		}
	} while (actual_length == 0);
	if (!strncmp("DJTAG1\n", (char *)rx_buf, 7)) {
		dirtyjtag_version = 1;
	} else if (!strncmp("DJTAG2\n", (char *)rx_buf, 7)) {
		dirtyjtag_version = 2;
	} else {
		LOG_INFO("dirtyJtag version unknown");
		dirtyjtag_version = 0;
	}
	LOG_INFO("dirtyjtag version %d", dirtyjtag_version);
	return ERROR_OK;
}

static int dirtyjtag_init(void)
{
	uint16_t avids[] = {dirtyjtag_vid, 0};
	uint16_t apids[] = {dirtyjtag_pid, 0};
	if (jtag_libusb_open(avids, apids, NULL, &usb_handle, NULL)) {
		LOG_ERROR("dirtyjtag not found: vid=%04x, pid=%04x\n", dirtyjtag_vid, dirtyjtag_pid);
		return ERROR_JTAG_INIT_FAILED;
	}
	if (jtag_libusb_choose_interface(usb_handle, &dirtyjtag_ep_read, &dirtyjtag_ep_write, -1,
									 -1, 0, LIBUSB_TRANSFER_TYPE_BULK)) {
		LOG_ERROR("unable to claim interface");
		return ERROR_JTAG_INIT_FAILED;
	}
	int res = dirtyjtag_getversion();
	if (res != ERROR_OK)
		return ERROR_JTAG_INIT_FAILED;
	if (dirtyjtag_version < 2) {
		LOG_ERROR("The probe appears to be running version 1 of DirtyJTAG. Please upgrade to DirtyJTAG 2.0 or newer.");
		return ERROR_JTAG_INIT_FAILED;
	}
	dirtyjtag_buffer_use = 0;
	if (dirtyjtag_init_bitq())
		return ERROR_JTAG_INIT_FAILED;
	return ERROR_OK;
}

static int dirtyjtag_quit(void)
{
	if (libusb_release_interface(usb_handle, 0) != 0)
		LOG_ERROR("usb release interface failed");
	jtag_libusb_close(usb_handle);
	return ERROR_OK;
}

static int dirtyjtag_speed_div(int divisor, int *khz)
{
	*khz = divisor;
	return ERROR_OK;
}

static int dirtyjtag_khz(int khz, int *divisor)
{
	if (khz == 0) {
		LOG_DEBUG("RCLK not supported");
		return ERROR_FAIL;
	}
	*divisor = (khz < 65535) ? khz : 65535;
	return ERROR_OK;
}
static int dirtyjtag_speed(int divisor)
{
	int res = dirtyjtag_buffer_flush();
	if (res != ERROR_OK)
		return res;
	uint8_t command[] = {CMD_FREQ, divisor >> 8, divisor};
	res = dirtyjtag_buffer_append(command, ARRAY_SIZE(command));
	if (res != ERROR_OK)
		return res;
	return dirtyjtag_buffer_flush();
}

static void write_tdi(int tdi, int tdo_req)
{
	/* we assume that the JTAG state machine is respected
	 * it isn't possible for tdo_req to change state without leaving
	 * OUTSTATE_XFER */
	if (tdo_req)
		djtg_bitq->tdo_in_expected++;
	djtg_bitq->current_command_array[buffer_pos_of_bit(djtg_bitq->tdi_out_count)] |=
		tdi << (7 - (djtg_bitq->tdi_out_count & 7));
	djtg_bitq->tdi_out_count++;
	if (djtg_bitq->tdi_out_count == djtg_bitq->max_tdi_count) {
		dirtyjtag_close_command(false);
		dirtyjtag_open_command(OUTSTATE_XFER);
	}
}

static int intf_bitq_out(int tms, int tdi, int tdo_req)
{
	switch (djtg_bitq->out_state) {
		case OUTSTATE_XFER:
			if (!tms) {
				write_tdi(tdi, tdo_req);
			} else {
				// This is the last of the scan bit (pause)
				dirtyjtag_close_command(false);
				dirtyjtag_open_command(OUTSTATE_CLK);
				if (tdo_req) {
					djtg_bitq->tdo_in_expected = 1;
					djtg_bitq->tdi_out_count = 1;
				}
				djtg_bitq->current_command_array[1] = (tdi ? SIG_TDI : 0) | (tms ? SIG_TMS : 0);
				djtg_bitq->current_command_array[2] = 1;
				djtg_bitq->out_state = OUTSTATE_CLK;
				dirtyjtag_close_command(false);
				dirtyjtag_open_command(OUTSTATE_CLK);
			}
			break;
		case OUTSTATE_CLK:
			if (!tdi && !tdo_req) {
				if (djtg_bitq->current_command_array[2]) {
					if (djtg_bitq->prev_tms == tms &&
						djtg_bitq->current_command_array[2] < 255) {
						djtg_bitq->current_command_array[2]++;
					} else {
						dirtyjtag_close_command(false);
						dirtyjtag_open_command(OUTSTATE_CLK);
					}
				}
				if (djtg_bitq->current_command_array[2] == 0) {
					/* first time for this command */
					djtg_bitq->current_command_array[1] = (tms ? SIG_TMS : 0);
					djtg_bitq->prev_tms = tms;
					djtg_bitq->current_command_array[2] = 1;
				}
			} else if (!tms) {
				djtg_bitq->out_state = OUTSTATE_XFER;
				dirtyjtag_close_command(false);
				dirtyjtag_open_command(OUTSTATE_XFER);
				write_tdi(tdi, tdo_req);
			} else {
				LOG_ERROR("tms at 1 unexpected");
			}
			break;
	}
	return 0;
}

static int intf_bitq_flush(void)
{
	int res = dirtyjtag_close_command(true);
	dirtyjtag_open_command(djtg_bitq->out_state);
	return res;
}

static int intf_bitq_in_rdy(void)
{
	return (djtg_bitq->in_command_idx < djtg_bitq->in_command_count);
}

static int intf_bitq_in(void)
{
	if (!intf_bitq_in_rdy())
		return -1;
	int res = (djtg_bitq->in_buffer[(djtg_bitq->in_bit_idx) / 8] &
			   BIT(7 - (djtg_bitq->in_bit_idx & 7)))
				  ? 1
				  : 0;
	djtg_bitq->in_bit_idx++;
	if (djtg_bitq->in_bit_idx >= djtg_bitq->in_bit_counts[djtg_bitq->in_command_idx]) {
		/* go to the next byte, skipping absent bits */
		djtg_bitq->in_bit_idx = ((djtg_bitq->in_bit_idx) + 7) & ~7;
		djtg_bitq->in_command_idx++;
		if (djtg_bitq->in_command_idx >= djtg_bitq->in_command_count) {
			/* we are at the end of the read. We can reset the read structures */
			djtg_bitq->in_command_count = 0;
			djtg_bitq->in_command_idx = 0;
			djtg_bitq->in_bit_idx = 0;
			djtg_bitq->in_buffer_fill = 0;
			djtg_bitq->expected_in_command_count = 0;
		}
	}
	return res;
}

static int intf_bitq_sleep(unsigned long us)
{
	int res = intf_bitq_flush();
	if (res != ERROR_OK)
		return res;
	jtag_sleep(us);
	return 0;
}

/**
 * Control /TRST and /SYSRST pins.
 * Perform immediate bitbang transaction.
 */
static int dirtyjtag_reset(int trst, int srst)
{
	uint8_t command[] = {
		CMD_SETSIG,
		SIG_TRST | SIG_SRST,
		(trst ? 0 : SIG_TRST) | (srst ? 0 : SIG_SRST)
	};

	LOG_DEBUG("(%d,%d)", trst, srst);
	int res = intf_bitq_flush();
	if (res != ERROR_OK)
		return res;
	res = dirtyjtag_buffer_append(command, ARRAY_SIZE(command));
	if (res != ERROR_OK)
		return res;
	return dirtyjtag_buffer_flush();
}

static struct bitq_interface dirtyjtag_bitq_interface = {
	.out = intf_bitq_out,
	.flush = intf_bitq_flush,
	.sleep = intf_bitq_sleep,
	.reset = NULL, /* obsolete entry point */
	.in_rdy = intf_bitq_in_rdy,
	.in = intf_bitq_in,
};

static struct jtag_interface dirtyjtag_interface = {
	.execute_queue = bitq_execute_queue,
};

struct adapter_driver dirtyjtag_adapter_driver = {
	.name = "dirtyjtag",
	.transport_ids = TRANSPORT_JTAG,
	.transport_preferred_id = TRANSPORT_JTAG,
	.init = dirtyjtag_init,
	.quit = dirtyjtag_quit,
	.speed = dirtyjtag_speed,
	.khz = dirtyjtag_khz,
	.speed_div = dirtyjtag_speed_div,
	.reset = dirtyjtag_reset,
	.jtag_ops = &dirtyjtag_interface,
};
