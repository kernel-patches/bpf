// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2021 Google LLC.
 */

#include <test_progs.h>
#include <cgroup_helpers.h>
#include <network_helpers.h>

#include "cgroup_export_errno_setsockopt.skel.h"
#include "cgroup_export_errno_getsockopt.skel.h"

#define SOL_CUSTOM	0xdeadbeef

static int zero;

static void test_setsockopt_set(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_set_eunatch = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that sets EUNATCH, assert that
	 * we actually get that error when we run setsockopt()
	 */
	link_set_eunatch = bpf_program__attach_cgroup(obj->progs.set_eunatch,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eunatch, "cg-attach-set_eunatch"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EUNATCH, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 1, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eunatch);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_set_and_get(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_set_eunatch = NULL, *link_get_errno = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that sets EUNATCH, and one that gets the
	 * previously set errno. Assert that we get the same errno back.
	 */
	link_set_eunatch = bpf_program__attach_cgroup(obj->progs.set_eunatch,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eunatch, "cg-attach-set_eunatch"))
		goto close_bpf_object;
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EUNATCH, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 2, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, EUNATCH, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eunatch);
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_default_zero(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_get_errno = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that gets the previously set errno.
	 * Assert that, without anything setting one, we get 0.
	 */
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_OK(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				  &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 1, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, 0, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_default_zero_and_set(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_get_errno = NULL, *link_set_eunatch = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that gets the previously set errno, and then
	 * one that sets the errno to EUNATCH. Assert that the get does not
	 * see EUNATCH set later, and does not prevent EUNATCH from being set.
	 */
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;
	link_set_eunatch = bpf_program__attach_cgroup(obj->progs.set_eunatch,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eunatch, "cg-attach-set_eunatch"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EUNATCH, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 2, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, 0, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_get_errno);
	bpf_link__destroy(link_set_eunatch);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_override(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_set_eunatch = NULL, *link_set_eisconn = NULL;
	struct bpf_link *link_get_errno = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that sets EUNATCH, then one that sets EISCONN,
	 * and then one that gets the exported errno. Assert both the syscall
	 * and the helper sees the last set errno.
	 */
	link_set_eunatch = bpf_program__attach_cgroup(obj->progs.set_eunatch,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eunatch, "cg-attach-set_eunatch"))
		goto close_bpf_object;
	link_set_eisconn = bpf_program__attach_cgroup(obj->progs.set_eisconn,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eisconn, "cg-attach-set_eisconn"))
		goto close_bpf_object;
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EISCONN, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 3, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, EISCONN, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eunatch);
	bpf_link__destroy(link_set_eisconn);
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_legacy_eperm(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_legacy_eperm = NULL, *link_get_errno = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that return a reject without setting errno
	 * (legacy reject), and one that gets the errno. Assert that for
	 * backward compatibility the syscall result in EPERM, and this
	 * is also visible to the helper.
	 */
	link_legacy_eperm = bpf_program__attach_cgroup(obj->progs.legacy_eperm,
						       cgroup_fd);
	if (!ASSERT_OK_PTR(link_legacy_eperm, "cg-attach-legacy_eperm"))
		goto close_bpf_object;
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EPERM, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 2, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, EPERM, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_legacy_eperm);
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_setsockopt_legacy_no_override(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_setsockopt *obj;
	struct bpf_link *link_set_eunatch = NULL, *link_legacy_eperm = NULL;
	struct bpf_link *link_get_errno = NULL;

	obj = cgroup_export_errno_setsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach setsockopt that sets EUNATCH, then one that return a reject
	 * without setting errno, and then one that gets the exported errno.
	 * Assert both the syscall and the helper's errno are unaffected by
	 * the second prog (i.e. legacy rejects does not override the errno
	 * to EPERM).
	 */
	link_set_eunatch = bpf_program__attach_cgroup(obj->progs.set_eunatch,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eunatch, "cg-attach-set_eunatch"))
		goto close_bpf_object;
	link_legacy_eperm = bpf_program__attach_cgroup(obj->progs.legacy_eperm,
						       cgroup_fd);
	if (!ASSERT_OK_PTR(link_legacy_eperm, "cg-attach-legacy_eperm"))
		goto close_bpf_object;
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_ERR(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
				   &zero, sizeof(int)), "setsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EUNATCH, "setsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 3, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, EUNATCH, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eunatch);
	bpf_link__destroy(link_legacy_eperm);
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_setsockopt__destroy(obj);
}

static void test_getsockopt_get(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_getsockopt *obj;
	struct bpf_link *link_get_errno = NULL;
	int buf;
	socklen_t optlen = sizeof(buf);

	obj = cgroup_export_errno_getsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach getsockopt that gets previously set errno. Assert that the
	 * error from kernel is in retval_value and not errno_value.
	 */
	link_get_errno = bpf_program__attach_cgroup(obj->progs.get_errno,
						    cgroup_fd);
	if (!ASSERT_OK_PTR(link_get_errno, "cg-attach-get_errno"))
		goto close_bpf_object;

	if (!ASSERT_ERR(getsockopt(sock_fd, SOL_CUSTOM, 0,
				   &buf, &optlen), "getsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EOPNOTSUPP, "getsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 1, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->errno_value, 0, "errno_value"))
		goto close_bpf_object;
	if (!ASSERT_EQ(obj->bss->retval_value, -EOPNOTSUPP, "errno_value"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_get_errno);

	cgroup_export_errno_getsockopt__destroy(obj);
}

static void test_getsockopt_override(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_getsockopt *obj;
	struct bpf_link *link_set_eisconn = NULL;
	int buf;
	socklen_t optlen = sizeof(buf);

	obj = cgroup_export_errno_getsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach getsockopt that sets errno to EISCONN. Assert that this
	 * overrides the value from kernel.
	 */
	link_set_eisconn = bpf_program__attach_cgroup(obj->progs.set_eisconn,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eisconn, "cg-attach-set_eisconn"))
		goto close_bpf_object;

	if (!ASSERT_ERR(getsockopt(sock_fd, SOL_CUSTOM, 0,
				   &buf, &optlen), "getsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EISCONN, "getsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 1, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eisconn);

	cgroup_export_errno_getsockopt__destroy(obj);
}

static void test_getsockopt_retval_no_clear_errno(int cgroup_fd, int sock_fd)
{
	struct cgroup_export_errno_getsockopt *obj;
	struct bpf_link *link_set_eisconn = NULL, *link_clear_retval = NULL;
	int buf;
	socklen_t optlen = sizeof(buf);

	obj = cgroup_export_errno_getsockopt__open_and_load();
	if (!ASSERT_OK_PTR(obj, "skel-load"))
		return;

	/* Attach getsockopt that sets errno to EISCONN, and one that clears
	 * retval. Assert that the clearing retval does not clear EISCONN.
	 */
	link_set_eisconn = bpf_program__attach_cgroup(obj->progs.set_eisconn,
						      cgroup_fd);
	if (!ASSERT_OK_PTR(link_set_eisconn, "cg-attach-set_eisconn"))
		goto close_bpf_object;
	link_clear_retval = bpf_program__attach_cgroup(obj->progs.clear_retval,
						       cgroup_fd);
	if (!ASSERT_OK_PTR(link_clear_retval, "cg-attach-clear_retval"))
		goto close_bpf_object;

	if (!ASSERT_ERR(getsockopt(sock_fd, SOL_CUSTOM, 0,
				   &buf, &optlen), "getsockopt"))
		goto close_bpf_object;
	if (!ASSERT_EQ(errno, EISCONN, "getsockopt-errno"))
		goto close_bpf_object;

	if (!ASSERT_EQ(obj->bss->invocations, 2, "invocations"))
		goto close_bpf_object;
	if (!ASSERT_FALSE(obj->bss->assertion_error, "assertion_error"))
		goto close_bpf_object;

close_bpf_object:
	bpf_link__destroy(link_set_eisconn);
	bpf_link__destroy(link_clear_retval);

	cgroup_export_errno_getsockopt__destroy(obj);
}

void test_cgroup_export_errno(void)
{
	int cgroup_fd = -1;
	int sock_fd = -1;

	cgroup_fd = test__join_cgroup("/cgroup_export_errno");
	if (!ASSERT_GE(cgroup_fd, 0, "cg-create"))
		goto close_fd;

	sock_fd = start_server(AF_INET, SOCK_DGRAM, NULL, 0, 0);
	if (!ASSERT_GE(sock_fd, 0, "start-server"))
		goto close_fd;

	if (test__start_subtest("setsockopt-set"))
		test_setsockopt_set(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-set_and_get"))
		test_setsockopt_set_and_get(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-default_zero"))
		test_setsockopt_default_zero(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-default_zero_and_set"))
		test_setsockopt_default_zero_and_set(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-override"))
		test_setsockopt_override(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-legacy_eperm"))
		test_setsockopt_legacy_eperm(cgroup_fd, sock_fd);

	if (test__start_subtest("setsockopt-legacy_no_override"))
		test_setsockopt_legacy_no_override(cgroup_fd, sock_fd);

	if (test__start_subtest("getsockopt-get"))
		test_getsockopt_get(cgroup_fd, sock_fd);

	if (test__start_subtest("getsockopt-override"))
		test_getsockopt_override(cgroup_fd, sock_fd);

	if (test__start_subtest("getsockopt-retval_no_clear_errno"))
		test_getsockopt_retval_no_clear_errno(cgroup_fd, sock_fd);

close_fd:
	close(cgroup_fd);
}
