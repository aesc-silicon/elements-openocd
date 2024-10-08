// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2019-2020 by Marc Schink <dev@zapb.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/log.h>
#include <target/rtt.h>

#include "rtt.h"

#define CHANNEL_NAME_SIZE	128

COMMAND_HANDLER(handle_rtt_setup_command)
{
	struct rtt_source source;

	const char *DEFAULT_ID = "SEGGER RTT";
	const char *selected_id;
	if (CMD_ARGC < 2 || CMD_ARGC > 3)
		return ERROR_COMMAND_SYNTAX_ERROR;
	if (CMD_ARGC == 2)
		selected_id = DEFAULT_ID;
	else
		selected_id = CMD_ARGV[2];

	source.find_cb = &target_rtt_find_control_block;
	source.read_cb = &target_rtt_read_control_block;
	source.start = &target_rtt_start;
	source.stop = &target_rtt_stop;
	source.read = &target_rtt_read_callback;
	source.write = &target_rtt_write_callback;
	source.read_channel_info = &target_rtt_read_channel_info;

	target_addr_t address;
	uint32_t size;

	COMMAND_PARSE_NUMBER(target_addr, CMD_ARGV[0], address);
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], size);

	rtt_register_source(source, get_current_target(CMD_CTX));

	if (rtt_setup(address, size, selected_id) != ERROR_OK)
		return ERROR_FAIL;

	return ERROR_OK;
}

COMMAND_HANDLER(handle_rtt_start_command)
{
	if (CMD_ARGC > 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (!rtt_configured()) {
		command_print(CMD, "RTT is not configured");
		return ERROR_FAIL;
	}

	return rtt_start();
}

COMMAND_HANDLER(handle_rtt_stop_command)
{
	if (CMD_ARGC > 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	return rtt_stop();
}

COMMAND_HANDLER(handle_rtt_polling_interval_command)
{
	if (CMD_ARGC == 0) {
		int ret;
		unsigned int interval;

		ret = rtt_get_polling_interval(&interval);

		if (ret != ERROR_OK) {
			command_print(CMD, "Failed to get polling interval");
			return ret;
		}

		command_print(CMD, "%u ms", interval);
	} else if (CMD_ARGC == 1) {
		int ret;
		unsigned int interval;

		COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], interval);
		ret = rtt_set_polling_interval(interval);

		if (ret != ERROR_OK) {
			command_print(CMD, "Failed to set polling interval");
			return ret;
		}
	} else {
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(handle_rtt_channels_command)
{
	int ret;
	char channel_name[CHANNEL_NAME_SIZE];
	const struct rtt_control *ctrl;
	struct rtt_channel_info info;

	if (!rtt_found_cb()) {
		command_print(CMD, "rtt: Control block not available");
		return ERROR_FAIL;
	}

	ctrl = rtt_get_control();

	command_print(CMD, "Channels: up=%u, down=%u", ctrl->num_up_channels,
		ctrl->num_down_channels);

	command_print(CMD, "Up-channels:");

	info.name = channel_name;
	info.name_length = sizeof(channel_name);

	for (unsigned int i = 0; i < ctrl->num_up_channels; i++) {
		ret = rtt_read_channel_info(i, RTT_CHANNEL_TYPE_UP, &info);

		if (ret != ERROR_OK)
			return ret;

		if (!info.size)
			continue;

		command_print(CMD, "%u: %s %u %u", i, info.name, info.size,
			info.flags);
	}

	command_print(CMD, "Down-channels:");

	for (unsigned int i = 0; i < ctrl->num_down_channels; i++) {
		ret = rtt_read_channel_info(i, RTT_CHANNEL_TYPE_DOWN, &info);

		if (ret != ERROR_OK)
			return ret;

		if (!info.size)
			continue;

		command_print(CMD, "%u: %s %u %u", i, info.name, info.size,
			info.flags);
	}

	return ERROR_OK;
}

COMMAND_HANDLER(handle_channel_list)
{
	char channel_name[CHANNEL_NAME_SIZE];
	const struct rtt_control *ctrl;
	struct rtt_channel_info info;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (!rtt_found_cb()) {
		command_print(CMD, "rtt: Control block not available");
		return ERROR_FAIL;
	}

	ctrl = rtt_get_control();

	info.name = channel_name;
	info.name_length = sizeof(channel_name);

	command_print(CMD, "{");

	for (unsigned int i = 0; i < ctrl->num_up_channels; i++) {
		int ret = rtt_read_channel_info(i, RTT_CHANNEL_TYPE_UP, &info);
		if (ret != ERROR_OK)
			return ret;

		if (!info.size)
			continue;

		command_print(CMD,
			"    {\n"
			"        name  %s\n"
			"        size  0x%" PRIx32 "\n"
			"        flags 0x%" PRIx32 "\n"
			"    }",
			info.name, info.size, info.flags);
	}

	command_print(CMD, "}\n{");

	for (unsigned int i = 0; i < ctrl->num_down_channels; i++) {
		int ret = rtt_read_channel_info(i, RTT_CHANNEL_TYPE_DOWN, &info);
		if (ret != ERROR_OK)
			return ret;

		if (!info.size)
			continue;

		command_print(CMD,
			"    {\n"
			"        name  %s\n"
			"        size  0x%" PRIx32 "\n"
			"        flags 0x%" PRIx32 "\n"
			"    }",
			info.name, info.size, info.flags);
	}

	command_print(CMD, "}");

	return ERROR_OK;
}

static const struct command_registration rtt_subcommand_handlers[] = {
	{
		.name = "setup",
		.handler = handle_rtt_setup_command,
		.mode = COMMAND_ANY,
		.help = "setup RTT",
		.usage = "<address> <size> [ID]"
	},
	{
		.name = "start",
		.handler = handle_rtt_start_command,
		.mode = COMMAND_EXEC,
		.help = "start RTT",
		.usage = ""
	},
	{
		.name = "stop",
		.handler = handle_rtt_stop_command,
		.mode = COMMAND_EXEC,
		.help = "stop RTT",
		.usage = ""
	},
	{
		.name = "polling_interval",
		.handler = handle_rtt_polling_interval_command,
		.mode = COMMAND_EXEC,
		.help = "show or set polling interval in ms",
		.usage = "[interval]"
	},
	{
		.name = "channels",
		.handler = handle_rtt_channels_command,
		.mode = COMMAND_EXEC,
		.help = "list available channels",
		.usage = ""
	},
	{
		.name = "channellist",
		.handler = handle_channel_list,
		.mode = COMMAND_EXEC,
		.help = "list available channels",
		.usage = ""
	},
	COMMAND_REGISTRATION_DONE
};

const struct command_registration rtt_target_command_handlers[] = {
	{
		.name = "rtt",
		.mode = COMMAND_EXEC,
		.help = "RTT target commands",
		.usage = "",
		.chain = rtt_subcommand_handlers
	},
	COMMAND_REGISTRATION_DONE
};
