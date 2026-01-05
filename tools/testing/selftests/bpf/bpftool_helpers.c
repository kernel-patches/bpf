// SPDX-License-Identifier: GPL-2.0-only
#include "bpftool_helpers.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define BPFTOOL_PATH			"./tools/sbin/bpftool"
#define BPFTOOL_FULL_CMD_MAX_LEN	512

static int run_command(char *command, bool get_output, char *output_buf, size_t output_max_len)
{
	FILE *f;
	int ret;

	f = popen(command, "r");
	if (!f)
		return 1;

	if (get_output)
		fread(output_buf, 1, output_max_len, f);
	ret = pclose(f);

	return ret;
}

int run_bpftool_command(char *args)
{
	char cmd[BPFTOOL_FULL_CMD_MAX_LEN];
	int ret;

	ret = snprintf(cmd, BPFTOOL_FULL_CMD_MAX_LEN, "%s %s > /dev/null 2>&1",
		       BPFTOOL_PATH, args);
	if (ret !=
	    strlen(BPFTOOL_PATH) + 1 + strlen(args) + strlen(" > /dev/null 2>&1")) {
		fprintf(stderr, "Failed to generate bpftool command\n");
		return 1;
	}

	return run_command(cmd, false, NULL, 0);
}

int get_bpftool_command_output(char *args, char *output_buf, size_t output_max_len)
{
	int ret;
	char cmd[BPFTOOL_FULL_CMD_MAX_LEN];

	ret = snprintf(cmd, BPFTOOL_FULL_CMD_MAX_LEN, "%s %s", BPFTOOL_PATH,
		       args);
	if (ret != strlen(args) + strlen(BPFTOOL_PATH) + 1) {
		fprintf(stderr, "Failed to generate bpftool command");
		return 1;
	}

	return run_command(cmd, true, output_buf, output_max_len);
}

