// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int var1 = -1;
int var2;
struct {
	int var3_1;
	__s64 var3_2;
} var3;
int libout1;

int lib_routine(void)
{
	libout1 =  var1 + var2 + var3.var3_1 + var3.var3_2;
	return libout1;
}

char LICENSE[] SEC("license") = "GPL";
int VERSION SEC("version") = 1;
