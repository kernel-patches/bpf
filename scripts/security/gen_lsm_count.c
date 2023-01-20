// SPDX-License-Identifier: GPL-2.0

/* NOTE: we really do want to use the kernel headers here */
#define __EXPORTED_HEADERS__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <linux/kconfig.h>

#define GEN_MAX_LSM_COUNT (				\
	/* Capabilities */				\
	IS_ENABLED(CONFIG_SECURITY) +			\
	IS_ENABLED(CONFIG_SECURITY_SELINUX) +		\
	IS_ENABLED(CONFIG_SECURITY_SMACK) +		\
	IS_ENABLED(CONFIG_SECURITY_TOMOYO) +		\
	IS_ENABLED(CONFIG_SECURITY_APPARMOR) +		\
	IS_ENABLED(CONFIG_SECURITY_YAMA) +		\
	IS_ENABLED(CONFIG_SECURITY_LOADPIN) +		\
	IS_ENABLED(CONFIG_SECURITY_SAFESETID) +		\
	IS_ENABLED(CONFIG_SECURITY_LOCKDOWN_LSM) + 	\
	IS_ENABLED(CONFIG_BPF_LSM) + \
	IS_ENABLED(CONFIG_SECURITY_LANDLOCK))

const char *progname;

static void usage(void)
{
	printf("usage: %s lsm_count.h\n", progname);
	exit(1);
}

int main(int argc, char *argv[])
{
	FILE *fout;

	progname = argv[0];

	if (argc < 2)
		usage();

	fout = fopen(argv[1], "w");
	if (!fout) {
		fprintf(stderr, "Could not open %s for writing:  %s\n",
			argv[1], strerror(errno));
		exit(2);
	}

	fprintf(fout, "#ifndef _LSM_COUNT_H_\n#define _LSM_COUNT_H_\n\n");
	fprintf(fout, "\n#define MAX_LSM_COUNT %d\n", GEN_MAX_LSM_COUNT);
	fprintf(fout, "#endif /* _LSM_COUNT_H_ */\n");
	exit(0);
}
