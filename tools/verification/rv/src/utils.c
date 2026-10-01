// SPDX-License-Identifier: GPL-2.0
/*
 * util functions.
 *
 * Copyright (C) 2022 Red Hat Inc, Daniel Bristot de Oliveira <bristot@kernel.org>
 */

#include <getopt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <utils.h>

struct config config;

#define MAX_MSG_LENGTH	1024

/**
 * err_msg - print an error message to the stderr
 */
void err_msg(const char *fmt, ...)
{
	char message[MAX_MSG_LENGTH];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s", message);
}

/**
 * debug_msg - print a debug message to stderr if debug is set
 */
void debug_msg(const char *fmt, ...)
{
	char message[MAX_MSG_LENGTH];
	va_list ap;

	if (!config.debug)
		return;

	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s", message);
}

/*
 * mon_usage - print usage
 */
void mon_usage(int exit_val, char *monitor_name, const char *fmt, ...)
{

	char message[1024];
	va_list ap;
	int i;

	static const char *const usage[] = {
		"",
		"	-h/--help: print this menu and the reactor list",
		"	-r/--reactor 'reactor': enables the 'reactor'",
		"	-s/--self: when tracing (-t), also trace rv command",
		"	-t/--trace: trace monitor's event",
		"	-v/--verbose: print debug messages",
		"",
		NULL,
	};

	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);

	fprintf(stderr, "  %s\n", message);

	fprintf(stderr, "\n  usage: rv mon %s [-h] [-q] [-r reactor] [-s] [-v]", monitor_name);

	for (i = 0; usage[i]; i++)
		fprintf(stderr, "%s\n", usage[i]);

	ikm_usage_print_reactors();
	exit(exit_val);
}

/*
 * parse_arguments - parse arguments and set config
 */
int parse_arguments(char *monitor_name, int argc, char **argv)
{
	int c;

	config.my_pid = getpid();

	while (1) {
		static struct option long_options[] = {
			{"help",		no_argument,		0, 'h'},
			{"reactor",		required_argument,	0, 'r'},
			{"self",		no_argument,		0, 's'},
			{"trace",		no_argument,		0, 't'},
			{"verbose",		no_argument,		0, 'v'},
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long(argc, argv, "hr:stv", long_options, &option_index);

		/* detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			mon_usage(0, monitor_name, "help:");
			break;
		case 'r':
			config.reactor = optarg;
			break;
		case 's':
			config.my_pid = -1;
			break;
		case 't':
			config.trace = 1;
			break;
		case 'v':
			config.debug = 1;
			break;
		}
	}

	debug_msg("ikm: my pid is %d\n", config.my_pid);

	return 0;
}
