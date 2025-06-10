// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

#include "unpriv_helpers.h"

static bool scan_config(const char *pat)
{
	bool ret = false;
	const char *msg;
	char buf[1024];
	gzFile config;
	int n, err;

	config = gzopen("/proc/config.gz", "rb");
	if (!config) {
		perror("gzopen /proc/config.gz");
		goto out;
	}
	for (;;) {
		if (!gzgets(config, buf, sizeof(buf))) {
			msg = gzerror(config, &err);
			if (err == Z_ERRNO)
				perror("gzgets /proc/config.gz");
			else if (err != Z_OK)
				fprintf(stderr, "gzgets /proc/config.gz: %s", msg);
			goto out;
		}
		n = strlen(buf);
		if (buf[n - 1] == '\n')
			buf[n - 1] = 0;
		if (strcmp(buf, pat) == 0) {
			ret = true;
			goto out;
		}
	}
out:
	gzclose(config);
	return ret;
}

static bool scan_cmdline(const char *pat)
{
	char cmdline[4096], *c;
	int fd, ret = false;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) {
		perror("open /proc/cmdline");
		return false;
	}

	if (read(fd, cmdline, sizeof(cmdline) - 1) < 0) {
		perror("read /proc/cmdline");
		goto out;
	}

	cmdline[sizeof(cmdline) - 1] = '\0';
	for (c = strtok(cmdline, " \n"); c; c = strtok(NULL, " \n")) {
		if (strncmp(c, pat, strlen(c)))
			continue;
		ret = true;
		break;
	}
out:
	close(fd);
	return ret;
}

static bool get_mitigations_off(void)
{
	return scan_cmdline("mitigations=off") || !scan_config("CONFIG_CPU_MITIGATIONS=y");
}

bool get_unpriv_disabled(void)
{
	bool disabled;
	char buf[2];
	FILE *fd;

	fd = fopen("/proc/sys/" UNPRIV_SYSCTL, "r");
	if (fd) {
		disabled = (fgets(buf, 2, fd) == buf && atoi(buf));
		fclose(fd);
	} else {
		perror("fopen /proc/sys/" UNPRIV_SYSCTL);
		disabled = true;
	}

	return disabled ? true : get_mitigations_off();
}
