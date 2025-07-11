// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <test_progs.h>
#include "signing.skel.h"
#include "fentry_test.lskel.h"

void test_signing(void)
{
struct signing *skel = NULL;
	struct fentry_test_lskel *lskel = NULL;
	int err;

	/* load a program that verifies the result of signing */
	skel = signing__open_and_load();
	if (!ASSERT_OK_PTR(skel, "signing_skel_load"))
		goto close_prog;

	err = signing__attach(skel);
	if (!ASSERT_OK(err, "signing_attach"))
		goto close_prog;

	/* Load a signed light skeleton */
	lskel = fentry_test_lskel__open_and_load();
	if (!ASSERT_OK_PTR(lskel, "signing_skel_load"))
		goto close_prog;

	err = fentry_test_lskel__attach(lskel);
	if (!ASSERT_OK(err, "signing_attach"))
		goto close_prog;

	ASSERT_OK(skel->data->sig_verify_retval, "bpf_prog_verify_signature");

close_prog:
	signing__destroy(skel);
	fentry_test_lskel__destroy(lskel);
}
