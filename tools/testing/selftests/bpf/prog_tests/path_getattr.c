// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <linux/stat.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <test_progs.h>

/* Userspace definition of the BTF-visible kfunc result. */
struct bpf_file_stat {
	__u64 ino;
	__u64 dev;
	__u64 mnt_id;
	__u64 size;
	__u64 attributes;
	__u64 attributes_mask;
	__u32 mode;
	__u32 uid;
	__u32 gid;
	__u32 result_mask;
};

#include "path_getattr.skel.h"
#include "verifier_path_getattr.skel.h"

#define STAT_FIELDS (STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID | \
		     STATX_INO | STATX_SIZE | STATX_MNT_ID | STATX_MNT_ID_UNIQUE)

static void query_stat(struct path_getattr *skel, const char *path)
{
	const struct bpf_file_stat *got = &skel->bss->output;
	struct statx stx;
	int err;

	memset(&skel->bss->output, 0xff, sizeof(skel->bss->output));
	skel->bss->calls = 0;
	skel->bss->monitored_tid = syscall(SYS_gettid);
	err = statx(AT_FDCWD, path, 0, skel->bss->request_mask, &stx);
	skel->bss->monitored_tid = 0;
	if (!ASSERT_OK(err, "statx") ||
	    !ASSERT_EQ(skel->bss->calls, 1, "hook_calls") ||
	    !ASSERT_OK(skel->bss->getattr_ret, "bpf_path_getattr"))
		return;
	ASSERT_EQ(got->ino, stx.stx_ino, "ino");
	ASSERT_EQ(got->dev, makedev(stx.stx_dev_major, stx.stx_dev_minor), "dev");
	ASSERT_EQ(got->mnt_id, stx.stx_mnt_id, "mnt_id");
	ASSERT_EQ(got->size, stx.stx_size, "size");
	ASSERT_EQ(got->mode, stx.stx_mode, "mode");
	ASSERT_EQ(got->uid, stx.stx_uid, "uid");
	ASSERT_EQ(got->gid, stx.stx_gid, "gid");
	ASSERT_EQ(got->attributes, stx.stx_attributes, "attributes");
	ASSERT_EQ(got->attributes_mask, stx.stx_attributes_mask, "attributes_mask");
	ASSERT_EQ(got->result_mask, stx.stx_mask & STAT_FIELDS, "result_mask");
}

static int create_file(const char *path)
{
	int fd, err;

	fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0640);
	if (!ASSERT_GE(fd, 0, "create_file"))
		return -1;
	err = ftruncate(fd, 12345);
	if (ASSERT_OK(err, "truncate_file"))
		err = fchown(fd, 123, 456);
	ASSERT_OK(err, "chown_file");
	close(fd);
	return err;
}

static void test_overlay(struct path_getattr *skel, const char *root)
{
	char lower[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], merged[PATH_MAX];
	char lower_file[PATH_MAX], merged_file[PATH_MAX], opts[PATH_MAX * 3 + 64];
	__u64 overlay_dev;
	int fd;

	snprintf(lower, sizeof(lower), "%s/lower", root);
	snprintf(upper, sizeof(upper), "%s/upper", root);
	snprintf(work, sizeof(work), "%s/work", root);
	snprintf(merged, sizeof(merged), "%s/merged", root);
	if (!ASSERT_OK(mkdir(lower, 0755), "mkdir_lower") ||
	    !ASSERT_OK(mkdir(upper, 0755), "mkdir_upper") ||
	    !ASSERT_OK(mkdir(work, 0755), "mkdir_work") ||
	    !ASSERT_OK(mkdir(merged, 0755), "mkdir_merged"))
		return;
	snprintf(lower_file, sizeof(lower_file), "%s/lower/file", root);
	snprintf(merged_file, sizeof(merged_file), "%s/merged/file", root);
	/*
	 * Distinct layer filesystems with xino disabled expose a different
	 * device for regular files than the overlay superblock's device.
	 */
	if (!ASSERT_OK(mount("tmpfs", lower, "tmpfs", 0, NULL), "mount_lower"))
		return;
	if (create_file(lower_file))
		goto out_lower;
	snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s,xino=off",
		 lower, upper, work);
	if (mount("overlay", merged, "overlay", 0, opts)) {
		if (errno == ENODEV || errno == EOPNOTSUPP) {
			printf("%s:SKIP: overlayfs unavailable: %s\n",
			       __func__, strerror(errno));
			test__skip();
			goto out_lower;
		}
		ASSERT_OK(-errno, "mount_overlay");
		goto out_lower;
	}
	skel->bss->request_mask = STATX_BASIC_STATS | STATX_MNT_ID;
	query_stat(skel, merged);
	overlay_dev = skel->bss->output.dev;
	query_stat(skel, merged_file);
	ASSERT_NEQ(skel->bss->output.dev, overlay_dev, "lower_layer_dev");
	/* Opening for write copies a lower-only file into the upper layer. */
	fd = open(merged_file, O_WRONLY | O_CLOEXEC);
	if (ASSERT_GE(fd, 0, "copy_up")) {
		ASSERT_OK(ftruncate(fd, 23456), "truncate_upper");
		close(fd);
		query_stat(skel, merged_file);
		ASSERT_NEQ(skel->bss->output.dev, overlay_dev, "upper_layer_dev");
	}
	umount(merged);
out_lower:
	umount(lower);
}

void test_path_getattr(void)
{
	char root[] = "/tmp/bpf_path_getattr.XXXXXX";
	struct path_getattr *skel;
	char file[PATH_MAX];
	int nsfd, cwdfd;

	skel = path_getattr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(path_getattr__attach(skel), "attach_skeleton"))
		goto out_skel;
	nsfd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (!ASSERT_GE(nsfd, 0, "save_mountns"))
		goto out_skel;
	cwdfd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (!ASSERT_GE(cwdfd, 0, "save_cwd"))
		goto out_ns;
	if (!ASSERT_OK(unshare(CLONE_NEWNS), "unshare_mountns"))
		goto out_cwd;
	if (!ASSERT_OK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), "private_mounts") ||
	    !ASSERT_OK_PTR(mkdtemp(root), "mkdtemp"))
		goto out_restore;
	if (!ASSERT_OK(mount("tmpfs", root, "tmpfs", 0, NULL), "mount_tmpfs"))
		goto out_dir;
	snprintf(file, sizeof(file), "%s/file", root);
	if (create_file(file))
		goto out_umount;
	if (test__start_subtest("stat_parity")) {
		skel->bss->request_mask = STATX_BASIC_STATS | STATX_MNT_ID;
		query_stat(skel, file);
		skel->bss->request_mask = STATX_BASIC_STATS | STATX_MNT_ID_UNIQUE;
		query_stat(skel, root);
	}
	if (test__start_subtest("overlay"))
		test_overlay(skel, root);
out_umount:
	umount2(root, MNT_DETACH);
out_dir:
	rmdir(root);
out_restore:
	ASSERT_OK(setns(nsfd, CLONE_NEWNS), "restore_mountns");
	/* setns() also resets the working directory. */
	ASSERT_OK(fchdir(cwdfd), "restore_cwd");
out_cwd:
	close(cwdfd);
out_ns:
	close(nsfd);
out_skel:
	path_getattr__destroy(skel);
}

void test_verifier_path_getattr(void)
{
	RUN_TESTS(verifier_path_getattr);
}
