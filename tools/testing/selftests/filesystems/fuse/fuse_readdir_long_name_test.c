// SPDX-License-Identifier: GPL-2.0
/*
 * List a FUSE directory whose first entry has a name that doesn't fit
 * into a single page of READDIR or READDIRPLUS reply, using a small
 * getdents64() buffer, and check that no entry goes missing.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "kselftest_harness.h"

#include "fuse_common.h"

#define LONG_INO	2
#define AFTER_INO	3
#define AFTER_NAME	"after"
#define FUSE_NAME_MAX	(PATH_MAX - 1)
#define GETDENTS_MAX	65536

struct linux_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

static char long_name[FUSE_NAME_MAX + 1];

static void fs_getattr(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	struct stat st = {};

	if (ino != FUSE_ROOT_ID) {
		fuse_reply_err(req, ENOENT);
		return;
	}
	st.st_ino = ino;
	st.st_mode = S_IFDIR | 0755;
	st.st_nlink = 2;
	fuse_reply_attr(req, &st, 0);
}

/* Whole entries from @off, as many as fit into @size. */
static void fill_dir(fuse_req_t req, size_t size, off_t off, bool plus)
{
	char *buf = malloc(size);
	size_t used = 0;

	if (!buf) {
		fuse_reply_err(req, ENOMEM);
		return;
	}

	for (; off < 2; off++) {
		const char *name = off ? AFTER_NAME : long_name;
		struct fuse_entry_param e = {};
		size_t len;

		e.ino = off ? AFTER_INO : LONG_INO;
		e.attr.st_ino = e.ino;
		e.attr.st_mode = S_IFREG | 0444;
		e.attr.st_nlink = 1;
		if (plus)
			len = fuse_add_direntry_plus(req, buf + used, size - used,
						     name, &e, off + 1);
		else
			len = fuse_add_direntry(req, buf + used, size - used,
						name, &e.attr, off + 1);
		if (len > size - used)
			break;
		used += len;
	}

	fuse_reply_buf(req, buf, used);
	free(buf);
}

static void fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t off, struct fuse_file_info *fi)
{
	fill_dir(req, size, off, false);
}

static void fs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t off, struct fuse_file_info *fi)
{
	fill_dir(req, size, off, true);
}

static const struct fuse_lowlevel_ops fs_ops = {
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
};

static const struct fuse_lowlevel_ops fs_ops_plus = {
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
	.readdirplus	= fs_readdirplus,
};

FIXTURE(readdir_long_name)
{
	struct fuse_common_ctx ctx;
};

FIXTURE_VARIANT(readdir_long_name)
{
	bool plus;
	size_t name_len;
};

/* The shortest names whose entries don't fit into a 4k page, and the longest. */
FIXTURE_VARIANT_ADD(readdir_long_name, readdir_4073)
{
	.plus = false,
	.name_len = 4073,
};
FIXTURE_VARIANT_ADD(readdir_long_name, readdir_name_max)
{
	.plus = false,
	.name_len = FUSE_NAME_MAX,
};
FIXTURE_VARIANT_ADD(readdir_long_name, readdirplus_3945)
{
	.plus = true,
	.name_len = 3945,
};
FIXTURE_VARIANT_ADD(readdir_long_name, readdirplus_name_max)
{
	.plus = true,
	.name_len = FUSE_NAME_MAX,
};

FIXTURE_SETUP(readdir_long_name)
{
	char err[MAX_ERR_MSG];

	memset(long_name, 'L', variant->name_len);
	long_name[variant->name_len] = '\0';

	if (fs_setup(variant->plus ? &fs_ops_plus : &fs_ops, &self->ctx, err))
		SKIP(return, "%s", err);
}

FIXTURE_TEARDOWN(readdir_long_name)
{
	fs_teardown(&self->ctx);
}

TEST_F(readdir_long_name, small_buffer)
{
	bool seen_long = false, seen_after = false;
	size_t size = 4096;
	char *buf = NULL;
	int fd;

	fd = open(self->ctx.mountpoint, O_RDONLY | O_DIRECTORY);
	ASSERT_GE(fd, 0);

	for (;;) {
		long n;

		buf = realloc(buf, size);
		ASSERT_NE(buf, NULL);
		n = syscall(SYS_getdents64, fd, buf, size);
		/* The next entry doesn't fit, try again with more room. */
		if (n < 0 && errno == EINVAL && size < GETDENTS_MAX) {
			size *= 2;
			continue;
		}
		ASSERT_GE(n, 0);
		if (!n)
			break;

		for (long off = 0; off < n;) {
			struct linux_dirent64 *d = (void *)(buf + off);

			if (!strcmp(d->d_name, long_name))
				seen_long = true;
			else if (!strcmp(d->d_name, AFTER_NAME))
				seen_after = true;
			off += d->d_reclen;
		}
	}

	free(buf);
	close(fd);
	EXPECT_TRUE(seen_long);
	EXPECT_TRUE(seen_after);
}

TEST_HARNESS_MAIN
