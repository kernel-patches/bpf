// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <test_progs.h>
#include <bpf/btf.h>
#include "cap_helpers.h"
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>

/* copied from include/uapi/linux/mount.h, as including it conflicts with
 * sys/mount.h include
 */
enum fsconfig_command {
	FSCONFIG_SET_FLAG       = 0,    /* Set parameter, supplying no value */
	FSCONFIG_SET_STRING     = 1,    /* Set parameter, supplying a string value */
	FSCONFIG_SET_BINARY     = 2,    /* Set parameter, supplying a binary blob value */
	FSCONFIG_SET_PATH       = 3,    /* Set parameter, supplying an object by path */
	FSCONFIG_SET_PATH_EMPTY = 4,    /* Set parameter, supplying an object by (empty) path */
	FSCONFIG_SET_FD         = 5,    /* Set parameter, supplying an object by fd */
	FSCONFIG_CMD_CREATE     = 6,    /* Invoke superblock creation */
	FSCONFIG_CMD_RECONFIGURE = 7,   /* Invoke superblock reconfiguration */
};

static inline int sys_fsopen(const char *fsname, unsigned flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

static inline int sys_fsconfig(int fs_fd, unsigned cmd, const char *key, const void *val, int aux)
{
	return syscall(__NR_fsconfig, fs_fd, cmd, key, val, aux);
}

static inline int sys_fsmount(int fs_fd, unsigned flags, unsigned ms_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, ms_flags);
}

static int drop_priv_caps(__u64 *old_caps)
{
	return cap_disable_effective((1ULL << CAP_BPF) |
				     (1ULL << CAP_PERFMON) |
				     (1ULL << CAP_NET_ADMIN) |
				     (1ULL << CAP_SYS_ADMIN), old_caps);
}

static int restore_priv_caps(__u64 old_caps)
{
	return cap_enable_effective(old_caps, NULL);
}

static int set_delegate_mask(int fs_fd, const char *key, __u64 mask)
{
	char buf[32];
	int err;

	snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mask);
	err = sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, key,
			   mask == ~0ULL ? "any" : buf, 0);
	if (err < 0)
		err = -errno;
	return err;
}

#define zclose(fd) do { if (fd >= 0) close(fd); fd = -1; } while (0)

struct bpffs_opts {
	__u64 cmds;
	__u64 maps;
	__u64 progs;
	__u64 attachs;
};

static int setup_bpffs_fd(struct bpffs_opts *opts)
{
	int fs_fd = -1, err;

	/* create VFS context */
	fs_fd = sys_fsopen("bpf", 0);
	if (!ASSERT_GE(fs_fd, 0, "fs_fd"))
		goto cleanup;

	/* set up token delegation mount options */
	err = set_delegate_mask(fs_fd, "delegate_cmds", opts->cmds);
	if (!ASSERT_OK(err, "fs_cfg_cmds"))
		goto cleanup;
	err = set_delegate_mask(fs_fd, "delegate_maps", opts->maps);
	if (!ASSERT_OK(err, "fs_cfg_maps"))
		goto cleanup;
	err = set_delegate_mask(fs_fd, "delegate_progs", opts->progs);
	if (!ASSERT_OK(err, "fs_cfg_progs"))
		goto cleanup;
	err = set_delegate_mask(fs_fd, "delegate_attachs", opts->attachs);
	if (!ASSERT_OK(err, "fs_cfg_attachs"))
		goto cleanup;

	return fs_fd;
cleanup:
	zclose(fs_fd);
	return -1;
}

static int materialize_bpffs_fd(int fs_fd)
{
	int mnt_fd, err;

	/* instantiate FS object */
	err = sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	if (err < 0)
		return -errno;

	/* create O_PATH fd for detached mount */
	mnt_fd = sys_fsmount(fs_fd, 0, 0);
	if (err < 0)
		return -errno;

	return mnt_fd;
}

/* send FD over Unix domain (AF_UNIX) socket */
static int sendfd(int sockfd, int fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1] = { fd }, err;
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	err = sendmsg(sockfd, &msg, 0);
	if (err < 0)
		err = -errno;
	if (!ASSERT_EQ(err, 1, "sendmsg"))
		return -EINVAL;

	return 0;
}

/* receive FD over Unix domain (AF_UNIX) socket */
static int recvfd(int sockfd, int *fd)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	int fds[1], err;
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	err = recvmsg(sockfd, &msg, 0);
	if (err < 0)
		err = -errno;
	if (!ASSERT_EQ(err, 1, "recvmsg"))
		return -EINVAL;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!ASSERT_OK_PTR(cmsg, "cmsg_null") ||
	    !ASSERT_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(fds)), "cmsg_len") ||
	    !ASSERT_EQ(cmsg->cmsg_level, SOL_SOCKET, "cmsg_level") ||
	    !ASSERT_EQ(cmsg->cmsg_type, SCM_RIGHTS, "cmsg_type"))
		return -EINVAL;

	memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));
	*fd = fds[0];

	return 0;
}

static ssize_t write_nointr(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

static int write_file(const char *path, const void *buf, size_t count)
{
	int fd;
	ssize_t ret;

	fd = open(path, O_WRONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	ret = write_nointr(fd, buf, count);
	close(fd);
	if (ret < 0 || (size_t)ret != count)
		return -1;

	return 0;
}

static int create_and_enter_userns(void)
{
	uid_t uid;
	gid_t gid;
	char map[100];

	uid = getuid();
	gid = getgid();

	if (unshare(CLONE_NEWUSER))
		return -1;

	if (write_file("/proc/self/setgroups", "deny", sizeof("deny") - 1) &&
	    errno != ENOENT)
		return -1;

	snprintf(map, sizeof(map), "0 %d 1", uid);
	if (write_file("/proc/self/uid_map", map, strlen(map)))
		return -1;


	snprintf(map, sizeof(map), "0 %d 1", gid);
	if (write_file("/proc/self/gid_map", map, strlen(map)))
		return -1;

	if (setgid(0))
		return -1;

	if (setuid(0))
		return -1;

	return 0;
}

typedef int (*child_callback_fn)(int);

static void child(int sock_fd, struct bpffs_opts *bpffs_opts, child_callback_fn callback)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	int mnt_fd = -1, fs_fd = -1, err = 0;

	/* setup userns with root mappings */
	err = create_and_enter_userns();
	if (!ASSERT_OK(err, "create_and_enter_userns"))
		goto cleanup;

	/* setup mountns to allow creating BPF FS (fsopen("bpf")) from unpriv process */
	err = unshare(CLONE_NEWNS);
	if (!ASSERT_OK(err, "create_mountns"))
		goto cleanup;

	err = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, 0);
	if (!ASSERT_OK(err, "remount_root"))
		goto cleanup;

	fs_fd = setup_bpffs_fd(bpffs_opts);
	if (!ASSERT_GE(fs_fd, 0, "setup_bpffs")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* pass BPF FS context object to parent */
	err = sendfd(sock_fd, fs_fd);
	if (!ASSERT_OK(err, "send_fs_fd"))
		goto cleanup;

	/* avoid mucking around with mount namespaces and mounting at
	 * well-known path, just get detach-mounted BPF FS fd back from parent
	 */
	err = recvfd(sock_fd, &mnt_fd);
	if (!ASSERT_OK(err, "recv_mnt_fd"))
		goto cleanup;

	/* do custom test logic with customly set up BPF FS instance */
	err = callback(mnt_fd);
	if (!ASSERT_OK(err, "test_callback"))
		goto cleanup;

	err = 0;
cleanup:
	zclose(sock_fd);
	zclose(mnt_fd);

	exit(-err);
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static void parent(int child_pid, int sock_fd)
{
	int fs_fd = -1, mnt_fd = -1, err;

	err = recvfd(sock_fd, &fs_fd);
	if (!ASSERT_OK(err, "recv_bpffs_fd"))
		goto cleanup;

	mnt_fd = materialize_bpffs_fd(fs_fd);
	if (!ASSERT_GE(mnt_fd, 0, "materialize_bpffs_fd")) {
		err = -EINVAL;
		goto cleanup;
	}
	zclose(fs_fd);

	/* pass BPF FS context object to parent */
	err = sendfd(sock_fd, mnt_fd);
	if (!ASSERT_OK(err, "send_mnt_fd"))
		goto cleanup;
	zclose(mnt_fd);

	err = wait_for_pid(child_pid);
	ASSERT_OK(err, "waitpid_child");

cleanup:
	zclose(sock_fd);
	zclose(fs_fd);
	zclose(mnt_fd);

	if (child_pid > 0)
		(void)kill(child_pid, SIGKILL);
}

static void subtest_userns(struct bpffs_opts *bpffs_opts, child_callback_fn cb)
{
	int sock_fds[2] = { -1, -1 };
	int child_pid, err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds);
	if (!ASSERT_OK(err, "socketpair"))
		goto cleanup;

	child_pid = fork();
	if (!ASSERT_GE(child_pid, 0, "fork"))
		goto cleanup;

	if (child_pid == 0) {
		zclose(sock_fds[0]);
		return child(sock_fds[1], bpffs_opts, cb);

	} else {
		zclose(sock_fds[1]);
		return parent(child_pid, sock_fds[0]);
	}

cleanup:
	zclose(sock_fds[0]);
	zclose(sock_fds[1]);
	if (child_pid > 0)
		(void)kill(child_pid, SIGKILL);
}

static int userns_map_create(int mnt_fd)
{
	LIBBPF_OPTS(bpf_map_create_opts, map_opts);
	int err, token_fd = -1, map_fd = -1;
	__u64 old_caps = 0;

	/* create BPF token from BPF FS mount */
	token_fd = bpf_token_create(mnt_fd, "", NULL);
	if (!ASSERT_GT(token_fd, 0, "token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* while inside non-init userns, we need both a BPF token *and*
	 * CAP_BPF inside current userns to create privileged map; let's test
	 * that neither BPF token alone nor namespaced CAP_BPF is sufficient
	 */
	err = drop_priv_caps(&old_caps);
	if (!ASSERT_OK(err, "drop_caps"))
		goto cleanup;

	/* no token, no CAP_BPF -> fail */
	map_opts.token_fd = 0;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "wo_token_wo_bpf", 0, 8, 1, &map_opts);
	if (!ASSERT_LT(map_fd, 0, "stack_map_wo_token_wo_cap_bpf_should_fail")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* token without CAP_BPF -> fail */
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "w_token_wo_bpf", 0, 8, 1, &map_opts);
	if (!ASSERT_LT(map_fd, 0, "stack_map_w_token_wo_cap_bpf_should_fail")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* get back effective local CAP_BPF (and CAP_SYS_ADMIN) */
	err = restore_priv_caps(old_caps);
	if (!ASSERT_OK(err, "restore_caps"))
		goto cleanup;

	/* CAP_BPF without token -> fail */
	map_opts.token_fd = 0;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "wo_token_w_bpf", 0, 8, 1, &map_opts);
	if (!ASSERT_LT(map_fd, 0, "stack_map_wo_token_w_cap_bpf_should_fail")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* finally, namespaced CAP_BPF + token -> success */
	map_opts.token_fd = token_fd;
	map_fd = bpf_map_create(BPF_MAP_TYPE_STACK, "w_token_w_bpf", 0, 8, 1, &map_opts);
	if (!ASSERT_GT(map_fd, 0, "stack_map_w_token_w_cap_bpf")) {
		err = -EINVAL;
		goto cleanup;
	}

cleanup:
	zclose(token_fd);
	zclose(map_fd);
	return err;
}

static int userns_btf_load(int mnt_fd)
{
	LIBBPF_OPTS(bpf_btf_load_opts, btf_opts);
	int err, token_fd = -1, btf_fd = -1;
	const void *raw_btf_data;
	struct btf *btf = NULL;
	__u32 raw_btf_size;
	__u64 old_caps = 0;

	/* create BPF token from BPF FS mount */
	token_fd = bpf_token_create(mnt_fd, "", NULL);
	if (!ASSERT_GT(token_fd, 0, "token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* while inside non-init userns, we need both a BPF token *and*
	 * CAP_BPF inside current userns to create privileged map; let's test
	 * that neither BPF token alone nor namespaced CAP_BPF is sufficient
	 */
	err = drop_priv_caps(&old_caps);
	if (!ASSERT_OK(err, "drop_caps"))
		goto cleanup;

	/* setup a trivial BTF data to load to the kernel */
	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_btf"))
		goto cleanup;

	ASSERT_GT(btf__add_int(btf, "int", 4, 0), 0, "int_type");

	raw_btf_data = btf__raw_data(btf, &raw_btf_size);
	if (!ASSERT_OK_PTR(raw_btf_data, "raw_btf_data"))
		goto cleanup;

	/* no token + no CAP_BPF -> failure */
	btf_opts.token_fd = 0;
	btf_fd = bpf_btf_load(raw_btf_data, raw_btf_size, &btf_opts);
	if (!ASSERT_LT(btf_fd, 0, "no_token_no_cap_should_fail"))
		goto cleanup;

	/* token + no CAP_BPF -> failure */
	btf_opts.token_fd = token_fd;
	btf_fd = bpf_btf_load(raw_btf_data, raw_btf_size, &btf_opts);
	if (!ASSERT_LT(btf_fd, 0, "token_no_cap_should_fail"))
		goto cleanup;

	/* get back effective local CAP_BPF (and CAP_SYS_ADMIN) */
	err = restore_priv_caps(old_caps);
	if (!ASSERT_OK(err, "restore_caps"))
		goto cleanup;

	/* token + CAP_BPF -> success */
	btf_opts.token_fd = token_fd;
	btf_fd = bpf_btf_load(raw_btf_data, raw_btf_size, &btf_opts);
	if (!ASSERT_GT(btf_fd, 0, "token_and_cap_success"))
		goto cleanup;

	err = 0;
cleanup:
	btf__free(btf);
	zclose(btf_fd);
	zclose(token_fd);
	return err;
}

static int userns_prog_load(int mnt_fd)
{
	LIBBPF_OPTS(bpf_prog_load_opts, prog_opts);
	int err, token_fd = -1, prog_fd = -1;
	struct bpf_insn insns[] = {
		/* bpf_jiffies64() requires CAP_BPF */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		/* bpf_get_current_task() requires CAP_PERFMON */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_task),
		/* r0 = 0; exit; */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	size_t insn_cnt = ARRAY_SIZE(insns);
	__u64 old_caps = 0;

	/* create BPF token from BPF FS mount */
	token_fd = bpf_token_create(mnt_fd, "", NULL);
	if (!ASSERT_GT(token_fd, 0, "token_create")) {
		err = -EINVAL;
		goto cleanup;
	}

	/* validate we can successfully load BPF program with token; this
	 * being XDP program (CAP_NET_ADMIN) using bpf_jiffies64() (CAP_BPF)
	 * and bpf_get_current_task() (CAP_PERFMON) helpers validates we have
	 * BPF token wired properly in a bunch of places in the kernel
	 */
	prog_opts.token_fd = token_fd;
	prog_opts.expected_attach_type = BPF_XDP;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_GT(prog_fd, 0, "prog_fd"))
		goto cleanup;

	/* no token + caps -> failure */
	prog_opts.token_fd = 0;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_EQ(prog_fd, -EPERM, "prog_fd_eperm"))
		goto cleanup;

	err = drop_priv_caps(&old_caps);
	if (!ASSERT_OK(err, "drop_caps"))
		goto cleanup;

	/* no caps + token -> failure */
	prog_opts.token_fd = token_fd;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_EQ(prog_fd, -EPERM, "prog_fd_eperm"))
		goto cleanup;

	/* no caps + no token -> definitely a failure */
	prog_opts.token_fd = 0;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "token_prog", "GPL",
				insns, insn_cnt, &prog_opts);
	if (!ASSERT_EQ(prog_fd, -EPERM, "prog_fd_eperm"))
		goto cleanup;

	err = 0;
cleanup:
	zclose(prog_fd);
	zclose(token_fd);
	return err;
}

void test_token(void)
{
	if (test__start_subtest("map_token")) {
		struct bpffs_opts opts = {
			.cmds = 1ULL << BPF_MAP_CREATE,
			.maps = 1ULL << BPF_MAP_TYPE_STACK,
		};

		subtest_userns(&opts, userns_map_create);
	}
	if (test__start_subtest("btf_token")) {
		struct bpffs_opts opts = {
			.cmds = 1ULL << BPF_BTF_LOAD,
		};

		subtest_userns(&opts, userns_btf_load);
	}
	if (test__start_subtest("prog_token")) {
		struct bpffs_opts opts = {
			.cmds = 1ULL << BPF_PROG_LOAD,
			.progs = 1ULL << BPF_PROG_TYPE_XDP,
			.attachs = 1ULL << BPF_XDP,
		};

		subtest_userns(&opts, userns_prog_load);
	}
}
