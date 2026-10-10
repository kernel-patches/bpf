// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#include <test_progs.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define ARENA_PAGES 4

struct arena_file {
	int map_fd;
	int file_fd;
	char pin[128];
	void *canonical;
	size_t len;
	bool pinned;
};

static void cleanup(struct arena_file *file)
{
	if (file->canonical != MAP_FAILED)
		munmap(file->canonical, file->len);
	if (file->file_fd >= 0)
		close(file->file_fd);
	if (file->pinned)
		unlink(file->pin);
	if (file->map_fd >= 0)
		close(file->map_fd);
}

static void reject_mapping(int fd, size_t len, int flags, off_t offset,
			   const char *name)
{
	void *addr;
	int err;

	addr = mmap(NULL, len, PROT_READ | PROT_WRITE, flags, fd, offset);
	err = errno;
	if (ASSERT_EQ(addr, MAP_FAILED, name))
		ASSERT_EQ(err, EINVAL, "mmap_errno");
	else
		munmap(addr, len);
}

static bool setup(struct arena_file *file, __u64 map_extra, bool zero)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE |
			     BPF_F_ARENA_EXPORT,
		.map_extra = map_extra);

	memset(file, 0, sizeof(*file));
	file->map_fd = -1;
	file->file_fd = -1;
	file->canonical = MAP_FAILED;
	file->len = ARENA_PAGES * getpagesize();
	snprintf(file->pin, sizeof(file->pin), "/sys/fs/bpf/arena_pinned_%d", getpid());
	file->map_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_pinned",
				      0, 0, ARENA_PAGES, &opts);
	if (file->map_fd < 0 && errno == EOPNOTSUPP) {
		test__skip();
		return false;
	}
	if (!ASSERT_GE(file->map_fd, 0, "map_create"))
		return false;
	if (!ASSERT_OK(bpf_obj_pin(file->map_fd, file->pin), "obj_pin"))
		return false;
	file->pinned = true;
	file->file_fd = open(file->pin, O_RDWR);
	if (!ASSERT_GE(file->file_fd, 0, "open_pin"))
		return false;
	reject_mapping(file->map_fd, getpagesize(), MAP_SHARED, 0, "short_canonical");
	reject_mapping(file->map_fd, file->len + getpagesize(), MAP_SHARED,
		       0, "large_canonical");
	if (map_extra)
		return true;

	reject_mapping(file->file_fd, getpagesize(), MAP_SHARED, 0, "uninitialized");
	file->canonical = mmap(NULL, file->len, PROT_READ | PROT_WRITE,
			       MAP_SHARED | (zero ? MAP_FIXED_NOREPLACE : 0),
			       file->map_fd, 0);
	if (zero && file->canonical == MAP_FAILED &&
	    (errno == EPERM || errno == EACCES)) {
		test__skip();
		return false;
	}
	return ASSERT_NEQ(file->canonical, MAP_FAILED, "canonical_mmap");
}

static void test_mappings(__u64 map_extra)
{
	struct arena_file file;
	size_t ps = getpagesize();
	struct stat st;
	char *alias = MAP_FAILED;
	char *full = MAP_FAILED;
	int expected = 91;

	if (!setup(&file, map_extra, false))
		goto out;
	if (!ASSERT_OK(fstat(file.file_fd, &st), "stat_pin"))
		goto out;
	ASSERT_EQ(st.st_size, ARENA_PAGES * ps, "pin_size");
	reject_mapping(file.file_fd, 8ULL << 30, MAP_SHARED, 0, "oversized");
	reject_mapping(file.file_fd, ps, MAP_SHARED, ARENA_PAGES * ps, "past_capacity");
	reject_mapping(file.file_fd, ps * 2, MAP_SHARED,
		       (ARENA_PAGES - 1) * ps, "past_capacity_end");
	reject_mapping(file.file_fd, ps, MAP_PRIVATE, 0, "private_mapping");
	full = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    file.file_fd, 0);
	if (!ASSERT_NEQ(full, MAP_FAILED, "full_file_mmap"))
		goto out;
	full[0] = 17;
	full[file.len - 1] = 62;

	alias = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED,
		     file.file_fd, (ARENA_PAGES - 1) * ps);
	if (!ASSERT_NEQ(alias, MAP_FAILED, "last_page_slice"))
		goto out;
	alias[0] = 91;
	ASSERT_OK(msync(alias, ps, MS_SYNC), "msync_slice");
	ASSERT_OK(fsync(file.file_fd), "fsync_pin");
	ASSERT_OK(fdatasync(file.file_fd), "fdatasync_pin");
	ASSERT_EQ(alias[ps - 1], 62, "full_file_last_page");
	if (file.canonical != MAP_FAILED) {
		char *canonical = file.canonical;

		ASSERT_EQ(canonical[0], 17, "full_file_first_page");
		ASSERT_EQ(canonical[(ARENA_PAGES - 1) * ps], 91, "alias_write");
		canonical[(ARENA_PAGES - 1) * ps] = 42;
		ASSERT_EQ(alias[0], 42, "canonical_write");
		expected = 42;
		if (!ASSERT_OK(munmap(file.canonical, file.len), "unmap_canonical"))
			goto out;
		file.canonical = MAP_FAILED;
	}
	if (!ASSERT_OK(munmap(full, file.len), "unmap_full_file"))
		goto out;
	full = MAP_FAILED;
	if (!ASSERT_OK(unlink(file.pin), "unlink_pin"))
		goto out;
	file.pinned = false;
	close(file.file_fd);
	file.file_fd = -1;
	close(file.map_fd);
	file.map_fd = -1;
	ASSERT_EQ(alias[0], expected, "unpin_lifetime");
	alias[0] = 73;
out:
	if (full != MAP_FAILED)
		munmap(full, file.len);
	if (alias != MAP_FAILED)
		munmap(alias, ps);
	cleanup(&file);
}

static void test_unexported_pin(__u32 flags)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_MMAPABLE | flags);
	char pin[128];
	struct stat st;
	char *canonical = MAP_FAILED;
	size_t ps = getpagesize();
	int map_fd, fd, err;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_unexported",
			       0, 0, ARENA_PAGES, &opts);
	if (map_fd < 0 && errno == EOPNOTSUPP) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(map_fd, 0, "unexported_create"))
		return;
	canonical = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (!ASSERT_NEQ(canonical, MAP_FAILED, "unexported_short_mmap"))
		goto out;
	canonical[0] = 42;
	ASSERT_EQ(canonical[0], 42, "unexported_short_access");
	snprintf(pin, sizeof(pin), "/sys/fs/bpf/arena_unexported_%d", getpid());
	if (!ASSERT_OK(bpf_obj_pin(map_fd, pin), "unexported_pin"))
		goto out;
	if (ASSERT_OK(stat(pin, &st), "unexported_stat"))
		ASSERT_EQ(st.st_size, 0, "unexported_size");
	fd = open(pin, O_RDONLY);
	err = errno;
	if (ASSERT_EQ(fd, -1, "unexported_open"))
		ASSERT_EQ(err, EIO, "unexported_open_errno");
	else
		close(fd);
	fd = bpf_obj_get(pin);
	if (ASSERT_GE(fd, 0, "unexported_obj_get"))
		close(fd);
	ASSERT_OK(unlink(pin), "unexported_unlink");
out:
	if (canonical != MAP_FAILED)
		munmap(canonical, ps);
	close(map_fd);
}

static void test_export_requires_no_free(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_MMAPABLE | BPF_F_ARENA_EXPORT);
	int fd;

	fd = bpf_map_create(BPF_MAP_TYPE_ARENA, "arena_export",
			    0, 0, ARENA_PAGES, &opts);
	if (fd == -EOPNOTSUPP) {
		test__skip();
		return;
	}
	ASSERT_EQ(fd, -EINVAL, "export_requires_no_free");
	if (fd >= 0)
		close(fd);
}

static void test_read_only(int flags)
{
	struct arena_file file;
	size_t ps = getpagesize();
	char *alias = MAP_FAILED;
	void *addr;
	int fd = -1, err, ret;

	if (!setup(&file, 0, false))
		goto out;
	if (!ASSERT_OK(fchmod(file.file_fd, 0400), "chmod_read_only"))
		goto out;
	fd = open(file.pin, O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open_read_only"))
		goto out;
	alias = mmap(NULL, ps, PROT_READ, flags, fd, ps);
	if (!ASSERT_NEQ(alias, MAP_FAILED, "read_only_mmap"))
		goto out;
	ASSERT_EQ(alias[0], 0, "read_only_fault");
	((char *)file.canonical)[ps] = 42;
	ASSERT_EQ(alias[0], 42, "read_only_shared_update");

	addr = mmap(NULL, ps, PROT_READ | PROT_WRITE, flags, fd, ps);
	err = errno;
	if (ASSERT_EQ(addr, MAP_FAILED, "read_only_writable_mmap"))
		ASSERT_EQ(err, EACCES, "read_only_writable_errno");
	else
		munmap(addr, ps);
	ret = mprotect(alias, ps, PROT_READ | PROT_WRITE);
	err = errno;
	ASSERT_EQ(ret, -1, "read_only_mprotect");
	ASSERT_EQ(err, EACCES, "read_only_mprotect_errno");
	addr = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, ps);
	err = errno;
	if (ASSERT_EQ(addr, MAP_FAILED, "read_only_private_mmap"))
		ASSERT_EQ(err, EINVAL, "read_only_private_errno");
	else
		munmap(addr, ps);

	close(fd);
	fd = -1;
	((char *)file.canonical)[ps] = 73;
	ASSERT_EQ(alias[0], 73, "read_only_after_close");
out:
	if (alias != MAP_FAILED)
		munmap(alias, ps);
	if (fd >= 0)
		close(fd);
	cleanup(&file);
}

static void test_fixed_size(void)
{
	struct arena_file file;
	size_t ps = getpagesize();
	struct stat st;
	unsigned char resident;
	char *alias = MAP_FAILED;
	int err, fd, ret;

	if (!setup(&file, 0, false))
		goto out;
	alias = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, file.file_fd, 0);
	if (!ASSERT_NEQ(alias, MAP_FAILED, "alias_mmap"))
		goto out;
	alias[0] = 42;
	ret = ftruncate(file.file_fd, 0);
	err = errno;
	ASSERT_EQ(ret, -1, "ftruncate_shrink");
	ASSERT_EQ(err, EINVAL, "ftruncate_shrink_errno");
	ret = ftruncate(file.file_fd, file.len + ps);
	err = errno;
	ASSERT_EQ(ret, -1, "ftruncate_grow");
	ASSERT_EQ(err, EINVAL, "ftruncate_grow_errno");
	ret = truncate(file.pin, 0);
	err = errno;
	ASSERT_EQ(ret, -1, "truncate_pin");
	ASSERT_EQ(err, EINVAL, "truncate_pin_errno");
	fd = open(file.pin, O_RDWR | O_TRUNC);
	err = errno;
	if (ASSERT_EQ(fd, -1, "open_trunc"))
		ASSERT_EQ(err, EINVAL, "open_trunc_errno");
	else
		close(fd);
	ASSERT_OK(ftruncate(file.file_fd, file.len), "ftruncate_same_size");
	if (!ASSERT_OK(mincore(alias, ps, &resident), "mincore"))
		goto out;
	ASSERT_EQ(resident & 1, 1, "mapping_not_zapped");
	ASSERT_EQ(alias[0], 42, "mapping_value");
	ASSERT_OK(fchmod(file.file_fd, 0640), "chmod_pin");
	if (ASSERT_OK(fstat(file.file_fd, &st), "stat_pin")) {
		ASSERT_EQ(st.st_size, file.len, "fixed_size");
		ASSERT_EQ(st.st_mode & 0777, 0640, "pin_mode");
	}
	ASSERT_EQ(lseek(file.file_fd, 0, SEEK_END), file.len, "seek_capacity");
	ASSERT_EQ(lseek(file.file_fd, -(off_t)ps, SEEK_CUR), file.len - ps, "seek_back");
	ASSERT_EQ(lseek(file.file_fd, ps, SEEK_SET), ps, "seek_offset");
	errno = 0;
	ASSERT_EQ(lseek(file.file_fd, file.len + 1, SEEK_SET), -1, "seek_past_end");
	ASSERT_EQ(errno, EINVAL, "seek_past_end_errno");
	errno = 0;
	ASSERT_EQ(lseek(file.file_fd, -1, SEEK_SET), -1, "seek_before_start");
	ASSERT_EQ(errno, EINVAL, "seek_before_start_errno");
	fd = bpf_obj_get(file.pin);
	if (ASSERT_GE(fd, 0, "obj_get_after_chmod"))
		close(fd);
out:
	if (alias != MAP_FAILED)
		munmap(alias, ps);
	cleanup(&file);
}

static void test_zero_canonical(void)
{
	struct arena_file file;
	size_t ps = getpagesize();
	char *alias = MAP_FAILED;
	void *addr;

	if (!setup(&file, 0, true))
		goto out;
	if (!ASSERT_EQ((unsigned long)file.canonical, 0, "zero_canonical"))
		goto out;
	alias = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_SHARED, file.file_fd, ps);
	if (!ASSERT_NEQ(alias, MAP_FAILED, "zero_canonical_export"))
		goto out;
	alias[0] = 42;
	ASSERT_EQ(alias[0], 42, "zero_canonical_fault");
	addr = mmap((void *)ps, file.len, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_FIXED_NOREPLACE, file.map_fd, 0);
	if (ASSERT_EQ(addr, MAP_FAILED, "canonical_cannot_move"))
		ASSERT_EQ(errno, EINVAL, "canonical_cannot_move_errno");
	else
		munmap(addr, file.len);
out:
	if (alias != MAP_FAILED)
		munmap(alias, ps);
	cleanup(&file);
}

static void test_lifecycle(void)
{
	struct arena_file file;
	size_t ps = getpagesize();
	char *alias = MAP_FAILED;
	void *target = MAP_FAILED, *addr;
	pid_t child;
	int status, ret, err;

	if (!setup(&file, 0, false))
		goto out;
	alias = mmap(NULL, ps * 2, PROT_READ | PROT_WRITE, MAP_SHARED,
		     file.file_fd, 0);
	if (!ASSERT_NEQ(alias, MAP_FAILED, "lifecycle_mmap"))
		goto out;
	alias[0] = 42;
	ret = munmap(alias, ps);
	err = errno;
	ASSERT_EQ(ret, -1, "partial_unmap");
	ASSERT_EQ(err, EINVAL, "partial_unmap_errno");
	ret = mprotect(alias, ps, PROT_READ);
	err = errno;
	ASSERT_EQ(ret, -1, "partial_mprotect");
	ASSERT_EQ(err, EINVAL, "partial_mprotect_errno");
	ret = madvise(alias, ps * 2, MADV_DOFORK);
	err = errno;
	ASSERT_EQ(ret, -1, "enable_inheritance");
	ASSERT_EQ(err, EINVAL, "enable_inheritance_errno");
	target = mmap(NULL, ps * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(target, MAP_FAILED, "reserve_remap_target"))
		goto out;
	addr = mremap(alias, ps * 2, ps * 2, MREMAP_MAYMOVE | MREMAP_FIXED, target);
	err = errno;
	if (!ASSERT_EQ(addr, MAP_FAILED, "relocate_mapping")) {
		alias = addr;
		target = MAP_FAILED;
	}
	ASSERT_EQ(err, EINVAL, "relocate_mapping_errno");
	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;
	if (!child) {
		unsigned char resident[2];

		ret = mincore(alias, ps * 2, resident);
		_exit(ret == -1 && errno == ENOMEM ? 0 : 1);
	}
	if (ASSERT_EQ(waitpid(child, &status, 0), child, "wait_child") &&
	    ASSERT_TRUE(WIFEXITED(status), "child_exited"))
		ASSERT_EQ(WEXITSTATUS(status), 0, "mapping_not_inherited");
	ASSERT_EQ(alias[0], 42, "parent_mapping_retained");
out:
	if (target != MAP_FAILED)
		munmap(target, ps * 2);
	if (alias != MAP_FAILED)
		munmap(alias, ps * 2);
	cleanup(&file);
}

void serial_test_arena_pinned(void)
{
	if (test__start_subtest("ordinary_pin"))
		test_unexported_pin(0);
	if (test__start_subtest("retained_pin"))
		test_unexported_pin(BPF_F_ARENA_NO_FREE);
	if (test__start_subtest("export_requires_no_free"))
		test_export_requires_no_free();
	if (test__start_subtest("mappings"))
		test_mappings(0);
	if (test__start_subtest("map_extra"))
		test_mappings(1ULL << 32);
	if (test__start_subtest("fixed_size"))
		test_fixed_size();
	if (test__start_subtest("read_only"))
		test_read_only(MAP_SHARED);
	if (test__start_subtest("read_only_validate"))
		test_read_only(MAP_SHARED_VALIDATE);
	if (test__start_subtest("zero_canonical"))
		test_zero_canonical();
	if (test__start_subtest("lifecycle"))
		test_lifecycle();
}
