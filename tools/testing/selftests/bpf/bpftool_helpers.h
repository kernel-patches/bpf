/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define MAX_BPFTOOL_CMD_LEN	(256)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

int run_bpftool_command(char *args);
int get_bpftool_command_output(char *args, char *output_buf, size_t output_max_len);
void test__start_subtest(const char *subtests_name);
void test__end_subtest(void);
void hijack_stdio(void);
void restore_stdio(void);
