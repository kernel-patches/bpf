// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>

struct fixture {
	char tmpfile[80];
	int fd;
	char *output;
	size_t sz;
};

static struct fixture *init_fixture(void)
{
	struct fixture *fix = malloc(sizeof(struct fixture));

	snprintf(fix->tmpfile, sizeof(fix->tmpfile), "/tmp/test_veristat.XXXXXX");
	fix->fd = mkstemp(fix->tmpfile);
	fix->sz = 1000000;
	fix->output = malloc(fix->sz);
	return fix;
}

static void teardown_fixture(struct fixture *fix)
{
	free(fix->output);
	close(fix->fd);
	remove(fix->tmpfile);
	free(fix);
}

void test_veristat_set_global_vars_succeeds(void)
{
	char command[512];
	struct fixture *fix = init_fixture();

	snprintf(command, sizeof(command),
		 "./veristat set_global_vars.bpf.o"\
		 " -G \"var_s64 = 0xf000000000000001\" "\
		 " -G \"var_u64 = 0xfedcba9876543210\" "\
		 " -G \"var_s32 = -0x80000000\" "\
		 " -G \"var_u32 = 0x76543210\" "\
		 " -G \"var_s16 = -32768\" "\
		 " -G \"var_u16 = 60652\" "\
		 " -G \"var_s8 = -128\" "\
		 " -G \"var_u8 = 255\" "\
		 " -G \"var_ea = EA2\" "\
		 " -G \"var_eb = EB2\" "\
		 " -G \"var_ec = EC2\" "\
		 " -G \"var_b = 1\" "\
		 "-vl2 > %s", fix->tmpfile);
	if (!ASSERT_EQ(0, system(command), "command"))
		goto out;

	read(fix->fd, fix->output, fix->sz);
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0xf000000000000001 "),
		   "var_s64 = 0xf000000000000001");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0xfedcba9876543210 "),
		   "var_u64 = 0xfedcba9876543210");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0x80000000 "), "var_s32 = -0x80000000");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0x76543210 "), "var_u32 = 0x76543210");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0x8000 "), "var_s16 = -32768");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0xecec "), "var_u16 = 60652");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=128 "), "var_s8 = -128");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=255 "), "var_u8 = 255");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=11 "), "var_ea = EA2");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=12 "), "var_eb = EB2");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=13 "), "var_ec = EC2");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=1 "), "var_b = 1");

out:
	teardown_fixture(fix);
}

void test_veristat_set_global_vars_from_file_succeeds(void)
{
	struct fixture *fix = init_fixture();
	char command[512];
	char input_file[80];
	const char *vars = "var_s16 = -32768\nvar_u16 = 60652";
	int fd;

	snprintf(input_file, sizeof(input_file), "/tmp/veristat_input.XXXXXX");
	fd = mkstemp(input_file);
	if (!ASSERT_GT(fd, 0, "valid fd"))
		goto out;

	write(fd, vars, strlen(vars));
	snprintf(command, sizeof(command),
		 "./veristat set_global_vars.bpf.o -G \"@%s\" -vl2 > %s",
		 input_file, fix->tmpfile);

	ASSERT_EQ(0, system(command), "command");
	read(fix->fd, fix->output, fix->sz);
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0x8000 "), "var_s16 = -32768");
	ASSERT_NEQ(NULL, strstr(fix->output, "_w=0xecec "), "var_u16 = 60652");

out:
	close(fd);
	remove(input_file);
	teardown_fixture(fix);
}

void test_veristat_set_global_vars_out_of_range(void)
{
	struct fixture *fix = init_fixture();
	char command[512];

	snprintf(command, sizeof(command),
		 "./veristat set_global_vars.bpf.o -G \"var_s32 = 2147483648\" -vl2 2> %s",
		 fix->tmpfile);

	if (!ASSERT_NEQ(0, system(command), "command"))
		goto out;

	read(fix->fd, fix->output, fix->sz);
	ASSERT_NEQ(NULL, strstr(fix->output, "is out of range [-2147483648; 2147483647]"),
		   "out of range");
out:
	teardown_fixture(fix);
}
