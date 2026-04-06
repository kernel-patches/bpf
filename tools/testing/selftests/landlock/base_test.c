// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Common user space base
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2019-2020 ANSSI
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "common.h"

#ifndef O_PATH
#define O_PATH 010000000
#endif

TEST(inconsistent_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *const buf = malloc(page_size + 1);
	struct landlock_ruleset_attr *const ruleset_attr = (void *)buf;

	ASSERT_NE(NULL, buf);

	/* Checks copy_from_user(). */
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 0, 0));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 1, 0));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 7, 0));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 1, 0));
	/* The size if less than sizeof(struct landlock_attr_enforce). */
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(
			      NULL, sizeof(struct landlock_ruleset_attr), 0));
	ASSERT_EQ(EFAULT, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size + 1, 0));
	ASSERT_EQ(E2BIG, errno);

	/* Checks minimal valid attribute size. */
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, 8, 0));
	ASSERT_EQ(ENOMSG, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(
			      ruleset_attr,
			      sizeof(struct landlock_ruleset_attr), 0));
	ASSERT_EQ(ENOMSG, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size, 0));
	ASSERT_EQ(ENOMSG, errno);

	/* Checks non-zero value. */
	buf[page_size - 2] = '.';
	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size, 0));
	ASSERT_EQ(E2BIG, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(ruleset_attr, page_size + 1, 0));
	ASSERT_EQ(E2BIG, errno);

	free(buf);
}

TEST(abi_version)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	ASSERT_EQ(10, landlock_create_ruleset(NULL, 0,
					     LANDLOCK_CREATE_RULESET_VERSION));

	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, 0,
					      LANDLOCK_CREATE_RULESET_VERSION));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, sizeof(ruleset_attr),
					      LANDLOCK_CREATE_RULESET_VERSION));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1,
		  landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					  LANDLOCK_CREATE_RULESET_VERSION));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 0,
					      LANDLOCK_CREATE_RULESET_VERSION |
						      1 << 31));
	ASSERT_EQ(EINVAL, errno);
}

static void add_read_rule(struct __test_metadata *const _metadata,
			  const int ruleset_fd, const char *const path)
{
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	path_beneath_attr.parent_fd = open(path, O_PATH | O_CLOEXEC);
	ASSERT_LE(0, path_beneath_attr.parent_fd);
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				       &path_beneath_attr, 0));
	ASSERT_EQ(0, close(path_beneath_attr.parent_fd));
}

static void add_read_rule_if_exists(struct __test_metadata *const _metadata,
				    const int ruleset_fd,
				    const char *const path)
{
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	path_beneath_attr.parent_fd = open(path, O_PATH | O_CLOEXEC);
	if (path_beneath_attr.parent_fd < 0) {
		ASSERT_TRUE(errno == ENOENT || errno == ENOTDIR ||
			    errno == EACCES);
		return;
	}
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				       &path_beneath_attr, 0));
	ASSERT_EQ(0, close(path_beneath_attr.parent_fd));
}

static void
add_exec_target_runtime_rules(struct __test_metadata *const _metadata,
			      const int ruleset_fd)
{
	static const char *const runtime_paths[] = {
		bin_exec_target, "/etc",     "/lib",
		"/lib64",	 "/usr/lib", "/usr/lib64",
	};
	size_t index;

	for (index = 0; index < ARRAY_SIZE(runtime_paths); index++)
		add_read_rule_if_exists(_metadata, ruleset_fd,
					runtime_paths[index]);
}

static int run_exec_target(const char *const mode, const char *const path)
{
	pid_t child;
	int status;
	char *const argv[] = {
		(char *)bin_exec_target,
		(char *)mode,
		(char *)path,
		NULL,
	};

	child = fork();
	if (child < 0)
		return -errno;
	if (!child) {
		execve(bin_exec_target, argv, NULL);
		_exit(errno);
	}
	if (waitpid(child, &status, 0) != child)
		return -errno;
	if (!WIFEXITED(status))
		return -ECHILD;
	return WEXITSTATUS(status);
}

static int create_temp_file(char path[static 32])
{
	int fd;

	strcpy(path, "/tmp/landlock-exectime-XXXXXX");
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (write(fd, "x", 1) != 1) {
		int err = errno;

		close(fd);
		unlink(path);
		return -err;
	}
	close(fd);
	return 0;
}

/*
 * Old source trees might not have the set of Kselftest fixes related to kernel
 * UAPI headers.
 */
#ifndef LANDLOCK_CREATE_RULESET_ERRATA
#define LANDLOCK_CREATE_RULESET_ERRATA (1U << 1)
#endif

TEST(errata)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int errata;

	errata = landlock_create_ruleset(NULL, 0,
					 LANDLOCK_CREATE_RULESET_ERRATA);
	/* The errata bitmask will not be backported to tests. */
	ASSERT_LE(0, errata);
	TH_LOG("errata: 0x%x", errata);

	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, 0,
					      LANDLOCK_CREATE_RULESET_ERRATA));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, sizeof(ruleset_attr),
					      LANDLOCK_CREATE_RULESET_ERRATA));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1,
		  landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					  LANDLOCK_CREATE_RULESET_ERRATA));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(
			      NULL, 0,
			      LANDLOCK_CREATE_RULESET_VERSION |
				      LANDLOCK_CREATE_RULESET_ERRATA));
	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 0,
					      LANDLOCK_CREATE_RULESET_ERRATA |
						      1 << 31));
	ASSERT_EQ(EINVAL, errno);
}

/* Tests ordering of syscall argument checks. */
TEST(create_ruleset_checks_ordering)
{
	const int last_flag = LANDLOCK_CREATE_RULESET_ERRATA;
	const int invalid_flag = last_flag << 1;
	int ruleset_fd;
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};

	/* Checks priority for invalid flags. */
	ASSERT_EQ(-1, landlock_create_ruleset(NULL, 0, invalid_flag));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, 0, invalid_flag));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1, landlock_create_ruleset(NULL, sizeof(ruleset_attr),
					      invalid_flag));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(-1,
		  landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr),
					  invalid_flag));
	ASSERT_EQ(EINVAL, errno);

	/* Checks too big ruleset_attr size. */
	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, -1, 0));
	ASSERT_EQ(E2BIG, errno);

	/* Checks too small ruleset_attr size. */
	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, 0, 0));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_create_ruleset(&ruleset_attr, 1, 0));
	ASSERT_EQ(EINVAL, errno);

	/* Checks valid call. */
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	ASSERT_EQ(0, close(ruleset_fd));
}

/* Tests ordering of syscall argument checks. */
TEST(add_rule_checks_ordering)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
	};
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
		.parent_fd = -1,
	};
	const int ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

	ASSERT_LE(0, ruleset_fd);

	/* Checks invalid flags. */
	ASSERT_EQ(-1, landlock_add_rule(-1, 0, NULL, 1));
	ASSERT_EQ(EINVAL, errno);

	/* Checks invalid ruleset FD. */
	ASSERT_EQ(-1, landlock_add_rule(-1, 0, NULL, 0));
	ASSERT_EQ(EBADF, errno);

	/* Checks invalid rule type. */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, 0, NULL, 0));
	ASSERT_EQ(EINVAL, errno);

	/* Checks invalid rule attr. */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
					NULL, 0));
	ASSERT_EQ(EFAULT, errno);

	/* Checks invalid path_beneath.parent_fd. */
	ASSERT_EQ(-1, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
					&path_beneath_attr, 0));
	ASSERT_EQ(EBADF, errno);

	/* Checks valid call. */
	path_beneath_attr.parent_fd =
		open("/tmp", O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath_attr.parent_fd);
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				       &path_beneath_attr, 0));
	ASSERT_EQ(0, close(path_beneath_attr.parent_fd));
	ASSERT_EQ(0, close(ruleset_fd));
}

/* Tests ordering of syscall argument and permission checks. */
TEST(restrict_self_checks_ordering)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
	};
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
		.parent_fd = -1,
	};
	const int ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	const int last_flag = LANDLOCK_RESTRICT_SELF_EXECTIME;
	const int invalid_flag = last_flag << 1;

	ASSERT_LE(0, ruleset_fd);
	path_beneath_attr.parent_fd =
		open("/tmp", O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath_attr.parent_fd);
	ASSERT_EQ(0, landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				       &path_beneath_attr, 0));
	ASSERT_EQ(0, close(path_beneath_attr.parent_fd));

	/* Checks unprivileged enforcement without no_new_privs. */
	drop_caps(_metadata);
	ASSERT_EQ(-1, landlock_restrict_self(-1, invalid_flag));
	ASSERT_EQ(EPERM, errno);
	ASSERT_EQ(-1, landlock_restrict_self(-1, 0));
	ASSERT_EQ(EPERM, errno);
	ASSERT_EQ(-1, landlock_restrict_self(ruleset_fd, 0));
	ASSERT_EQ(EPERM, errno);
	ASSERT_EQ(-1, landlock_restrict_self(
			     ruleset_fd,
			     LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME));
	ASSERT_EQ(EPERM, errno);

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	/* Checks invalid flags. */
	ASSERT_EQ(-1, landlock_restrict_self(-1, invalid_flag));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_restrict_self(
			     ruleset_fd,
			     LANDLOCK_RESTRICT_SELF_TSYNC |
				     LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, landlock_restrict_self(
			     ruleset_fd,
			     LANDLOCK_RESTRICT_SELF_TSYNC |
				     LANDLOCK_RESTRICT_SELF_EXECTIME));
	ASSERT_EQ(EINVAL, errno);

	/* Checks invalid ruleset FD. */
	ASSERT_EQ(-1, landlock_restrict_self(-1, 0));
	ASSERT_EQ(EBADF, errno);

	/* Checks valid call. */
	ASSERT_EQ(0, landlock_restrict_self(ruleset_fd, 0));
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(restrict_self_fd)
{
	int fd;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);

	EXPECT_EQ(-1, landlock_restrict_self(fd, 0));
	EXPECT_EQ(EBADFD, errno);
}

TEST(restrict_self_fd_logging_flags)
{
	int fd;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);

	/*
	 * LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF accepts -1 but not any file
	 * descriptor.
	 */
	EXPECT_EQ(-1, landlock_restrict_self(
			      fd, LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
	EXPECT_EQ(EBADFD, errno);
}

TEST(restrict_self_logging_flags)
{
	const __u32 last_flag = LANDLOCK_RESTRICT_SELF_EXECTIME;

	/* Tests invalid flag combinations. */

	EXPECT_EQ(-1, landlock_restrict_self(-1, last_flag << 1));
	EXPECT_EQ(EINVAL, errno);

	EXPECT_EQ(-1, landlock_restrict_self(-1, -1));
	EXPECT_EQ(EINVAL, errno);

	EXPECT_EQ(-1, landlock_restrict_self(
			      -1, LANDLOCK_RESTRICT_SELF_TSYNC |
				      LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME));
	EXPECT_EQ(EINVAL, errno);

	EXPECT_EQ(-1, landlock_restrict_self(
			      -1, LANDLOCK_RESTRICT_SELF_TSYNC |
				      LANDLOCK_RESTRICT_SELF_EXECTIME));
	EXPECT_EQ(EINVAL, errno);
	/* Tests valid flag combinations. */

	EXPECT_EQ(-1, landlock_restrict_self(-1, 0));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(-1, landlock_restrict_self(
			      -1, LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(-1,
		  landlock_restrict_self(
			  -1,
			  LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |
				  LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(-1,
		  landlock_restrict_self(
			  -1,
			  LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON |
				  LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(-1, landlock_restrict_self(
			      -1, LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(-1,
		  landlock_restrict_self(
			  -1, LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF |
				      LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON));
	EXPECT_EQ(EBADF, errno);

	/* Tests with an invalid ruleset_fd. */

	EXPECT_EQ(-1, landlock_restrict_self(
			      -2, LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
	EXPECT_EQ(EBADF, errno);

	EXPECT_EQ(0, landlock_restrict_self(
			     -1, LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF));
}

TEST(restrict_self_nnp_exectime_requires_no_new_privs_or_cap_sys_admin)
{
	const struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	const int ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);

	ASSERT_LE(0, ruleset_fd);
	drop_caps(_metadata);
	ASSERT_EQ(-1, landlock_restrict_self(
			     ruleset_fd,
			     LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME));
	ASSERT_EQ(EPERM, errno);
	ASSERT_EQ(0, close(ruleset_fd));
}

TEST(restrict_self_exectime_delays_enforcement)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	char path[32];
	int err;
	int ruleset_fd;
	int fd;

	err = create_temp_file(path);
	ASSERT_EQ(0, err);

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	add_exec_target_runtime_rules(_metadata, ruleset_fd);
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_EXECTIME));
	ASSERT_EQ(0, close(ruleset_fd));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));

	ASSERT_EQ(EACCES, run_exec_target("read", path));
	ASSERT_EQ(0, unlink(path));
}

TEST(restrict_self_exectime_failed_exec_keeps_pending_domain)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	char path[32];
	pid_t child;
	int err;
	int ruleset_fd;
	int status;

	err = create_temp_file(path);
	ASSERT_EQ(0, err);

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	add_exec_target_runtime_rules(_metadata, ruleset_fd);

	child = fork();
	ASSERT_LE(0, child);
	if (!child) {
		char *const exec_argv[] = {
			(char *)bin_exec_target,
			(char *)"read",
			path,
			NULL,
		};

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			_exit(errno);
		if (landlock_restrict_self(ruleset_fd,
					  LANDLOCK_RESTRICT_SELF_EXECTIME))
			_exit(errno);
		close(ruleset_fd);

		execve("/tmp/landlock-exectime-no-such-binary",
		       (char *const[]){ (char *)"/tmp/landlock-exectime-no-such-binary",
				       NULL },
		       NULL);
		if (errno != ENOENT)
			_exit(errno);

		execve(bin_exec_target, exec_argv, NULL);
		_exit(errno);
	}

	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(EACCES, WEXITSTATUS(status));
	ASSERT_EQ(0, close(ruleset_fd));
	ASSERT_EQ(0, unlink(path));
}

TEST(restrict_self_exectime_clones_ruleset)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	char path[32];
	int err;
	int ruleset_fd;

	err = create_temp_file(path);
	ASSERT_EQ(0, err);

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	add_exec_target_runtime_rules(_metadata, ruleset_fd);
	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_EXECTIME));

	add_read_rule(_metadata, ruleset_fd, path);
	ASSERT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, access(path, R_OK));
	ASSERT_EQ(EACCES, run_exec_target("read", path));
	ASSERT_EQ(0, unlink(path));
}

TEST(restrict_self_exectime_layers_on_exec)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	char path_before[32];
	char path_after[32];
	int err;
	int fd;
	int base_ruleset_fd;
	int staged_ruleset_fd;

	err = create_temp_file(path_before);
	ASSERT_EQ(0, err);
	err = create_temp_file(path_after);
	ASSERT_EQ(0, err);

	base_ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, base_ruleset_fd);
	staged_ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, staged_ruleset_fd);

	add_exec_target_runtime_rules(_metadata, base_ruleset_fd);
	add_exec_target_runtime_rules(_metadata, staged_ruleset_fd);
	add_read_rule(_metadata, base_ruleset_fd, path_before);
	add_read_rule(_metadata, staged_ruleset_fd, path_after);

	ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(base_ruleset_fd, 0));
	ASSERT_EQ(0, close(base_ruleset_fd));

	fd = open(path_before, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));
	ASSERT_EQ(-1, open(path_after, O_RDONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	ASSERT_EQ(0, landlock_restrict_self(staged_ruleset_fd,
				    LANDLOCK_RESTRICT_SELF_EXECTIME));
	ASSERT_EQ(0, close(staged_ruleset_fd));

	fd = open(path_before, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));
	ASSERT_EQ(-1, open(path_after, O_RDONLY | O_CLOEXEC));
	ASSERT_EQ(EACCES, errno);

	ASSERT_EQ(EACCES, run_exec_target("read", path_before));
	ASSERT_EQ(EACCES, run_exec_target("read", path_after));
	ASSERT_EQ(0, unlink(path_before));
	ASSERT_EQ(0, unlink(path_after));
}

TEST(restrict_self_exectime_rejects_layer_overflow)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	pid_t child;
	int ruleset_fd;
	int status;

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	child = fork();
	ASSERT_LE(0, child);
	if (!child) {
		int i;

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			_exit(errno);

		for (i = 0; i < 16; i++) {
			if (landlock_restrict_self(ruleset_fd, 0))
				_exit(errno);
		}

		if (!landlock_restrict_self(ruleset_fd,
					   LANDLOCK_RESTRICT_SELF_EXECTIME))
			_exit(0);
		_exit(errno);
	}

	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(E2BIG, WEXITSTATUS(status));
	ASSERT_EQ(0, close(ruleset_fd));
}
TEST(restrict_self_nnp_exectime_sets_nnp_on_exec)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	char path[32];
	int err;
	int fd;
	int ruleset_fd;

	err = create_temp_file(path);
	ASSERT_EQ(0, err);
	disable_caps(_metadata);
	ASSERT_EQ(0, prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	add_exec_target_runtime_rules(_metadata, ruleset_fd);
	set_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, landlock_restrict_self(
			     ruleset_fd,
			     LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS_EXECTIME));
	clear_cap(_metadata, CAP_SYS_ADMIN);
	ASSERT_EQ(0, close(ruleset_fd));

	ASSERT_EQ(0, prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
	fd = open(bin_exec_target, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));
	ASSERT_EQ(EACCES, run_exec_target("read", path));
	ASSERT_EQ(0, run_exec_target("nnp", NULL));
	ASSERT_EQ(0, unlink(path));
}
TEST(ruleset_fd_io)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd;
	char buf;

	drop_caps(_metadata);
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);

	ASSERT_EQ(-1, write(ruleset_fd, ".", 1));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, read(ruleset_fd, &buf, 1));
	ASSERT_EQ(EINVAL, errno);

	ASSERT_EQ(0, close(ruleset_fd));
}

/* Tests enforcement of a ruleset FD transferred through a UNIX socket. */
TEST(ruleset_fd_transfer)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	struct landlock_path_beneath_attr path_beneath_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int ruleset_fd_tx, dir_fd;
	int socket_fds[2];
	pid_t child;
	int status;

	drop_caps(_metadata);

	/* Creates a test ruleset with a simple rule. */
	ruleset_fd_tx =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd_tx);
	path_beneath_attr.parent_fd =
		open("/tmp", O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, path_beneath_attr.parent_fd);
	ASSERT_EQ(0,
		  landlock_add_rule(ruleset_fd_tx, LANDLOCK_RULE_PATH_BENEATH,
				    &path_beneath_attr, 0));
	ASSERT_EQ(0, close(path_beneath_attr.parent_fd));

	/* Sends the ruleset FD over a socketpair and then close it. */
	ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
				socket_fds));
	ASSERT_EQ(0, send_fd(socket_fds[0], ruleset_fd_tx));
	ASSERT_EQ(0, close(socket_fds[0]));
	ASSERT_EQ(0, close(ruleset_fd_tx));

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		const int ruleset_fd_rx = recv_fd(socket_fds[1]);

		ASSERT_LE(0, ruleset_fd_rx);
		ASSERT_EQ(0, close(socket_fds[1]));

		/* Enforces the received ruleset on the child. */
		ASSERT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		ASSERT_EQ(0, landlock_restrict_self(ruleset_fd_rx, 0));
		ASSERT_EQ(0, close(ruleset_fd_rx));

		/* Checks that the ruleset enforcement. */
		ASSERT_EQ(-1, open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		ASSERT_EQ(EACCES, errno);
		dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		ASSERT_LE(0, dir_fd);
		ASSERT_EQ(0, close(dir_fd));
		_exit(_metadata->exit_code);
		return;
	}

	ASSERT_EQ(0, close(socket_fds[1]));

	/* Checks that the parent is unrestricted. */
	dir_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, dir_fd);
	ASSERT_EQ(0, close(dir_fd));
	dir_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_LE(0, dir_fd);
	ASSERT_EQ(0, close(dir_fd));

	ASSERT_EQ(child, waitpid(child, &status, 0));
	ASSERT_EQ(1, WIFEXITED(status));
	ASSERT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
}

TEST(cred_transfer)
{
	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_DIR,
	};
	int ruleset_fd, dir_fd;
	pid_t child;
	int status;

	drop_caps(_metadata);

	dir_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	EXPECT_LE(0, dir_fd);
	EXPECT_EQ(0, close(dir_fd));

	/* Denies opening directories. */
	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	ASSERT_LE(0, ruleset_fd);
	EXPECT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
	ASSERT_EQ(0, landlock_restrict_self(ruleset_fd, 0));
	EXPECT_EQ(0, close(ruleset_fd));

	/* Checks ruleset enforcement. */
	EXPECT_EQ(-1, open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	EXPECT_EQ(EACCES, errno);

	/* Needed for KEYCTL_SESSION_TO_PARENT permission checks */
	EXPECT_NE(-1, syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL, 0,
			      0, 0))
	{
		TH_LOG("Failed to join session keyring: %s", strerror(errno));
	}

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		/* Checks ruleset enforcement. */
		EXPECT_EQ(-1, open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		EXPECT_EQ(EACCES, errno);

		/*
		 * KEYCTL_SESSION_TO_PARENT is a no-op unless we have a
		 * different session keyring in the child, so make that happen.
		 */
		EXPECT_NE(-1, syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING,
				      NULL, 0, 0, 0));

		/*
		 * KEYCTL_SESSION_TO_PARENT installs credentials on the parent
		 * that never go through the cred_prepare hook, this path uses
		 * cred_transfer instead.
		 */
		EXPECT_EQ(0, syscall(__NR_keyctl, KEYCTL_SESSION_TO_PARENT, 0,
				     0, 0, 0));

		/* Re-checks ruleset enforcement. */
		EXPECT_EQ(-1, open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
		EXPECT_EQ(EACCES, errno);

		_exit(_metadata->exit_code);
		return;
	}

	EXPECT_EQ(child, waitpid(child, &status, 0));
	EXPECT_EQ(1, WIFEXITED(status));
	EXPECT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));

	/* Re-checks ruleset enforcement. */
	EXPECT_EQ(-1, open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	EXPECT_EQ(EACCES, errno);
}

TEST_HARNESS_MAIN
