// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */

#include <test_progs.h>
#include <bpf/libbpf.h>

#include "test_subskeleton_lib.skel.h"

void subskeleton_lib_setup(struct bpf_object *obj)
{
	struct test_subskeleton_lib *lib = test_subskeleton_lib__open(obj);

	ASSERT_OK_PTR(lib, "open subskeleton");

	*lib->data.var1 = 1;
	*lib->bss.var2 = 2;
	lib->bss.var3->var3_1 = 3;
	lib->bss.var3->var3_2 = 4;
}

int subskeleton_lib_subresult(struct bpf_object *obj)
{
	struct test_subskeleton_lib *lib = test_subskeleton_lib__open(obj);

	ASSERT_OK_PTR(lib, "open subskeleton");

	ASSERT_EQ(*lib->bss.libout1, 1 + 2 + 3 + 4, "lib subresult");
	return *lib->bss.libout1;
}
