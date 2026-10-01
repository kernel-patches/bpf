// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>

#define MAX_PATH		1024

void debug_msg(const char *fmt, ...);
void err_msg(const char *fmt, ...);
void mon_usage(int exit_val, char *monitor_name, const char *fmt, ...);
int parse_arguments(char *monitor_name, int argc, char **argv);

void ikm_usage_print_reactors(void);

struct config {
	bool debug;
	bool is_container;
	bool trace;
	int has_id;
	int my_pid;
	char *initial_reactor;
	char *reactor;
};
extern struct config config;
