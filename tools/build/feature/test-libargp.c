// SPDX-License-Identifier: GPL-2.0
#include <argp.h>

const char *argp_program_version = "test-libargp";
static const struct argp_option opts[] = { {} };

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
	};
	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	return 0;
}
