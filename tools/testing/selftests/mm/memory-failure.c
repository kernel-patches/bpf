// SPDX-License-Identifier: GPL-2.0
/*
 * Memory-failure functional tests.
 *
 * Author(s): Miaohe Lin <linmiaohe@huawei.com>
 */

#include "../kselftest_harness.h"

#include <sys/mman.h>
#include <linux/mman.h>
#include <linux/string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <errno.h>
#include <stdlib.h>

#include "vm_util.h"

enum inject_type {
	MADV_HARD,
	MADV_SOFT,
};

enum result_type {
	MADV_HARD_ANON,
	MADV_HARD_CLEAN_PAGECACHE,
	MADV_HARD_DIRTY_PAGECACHE,
	MADV_HARD_CLEAN_SHMEM,
	MADV_HARD_DIRTY_SHMEM,
	MADV_SOFT_ANON,
	MADV_SOFT_CLEAN_PAGECACHE,
	MADV_SOFT_DIRTY_PAGECACHE,
	MADV_SOFT_CLEAN_SHMEM,
	MADV_SOFT_DIRTY_SHMEM,
	READ_ERROR,
};

static jmp_buf signal_jmp_buf;
static siginfo_t siginfo;
const char *pagemap_proc = "/proc/self/pagemap";
const char *kpageflags_proc = "/proc/kpageflags";

FIXTURE(memory_failure)
{
	unsigned long page_size;
	unsigned long corrupted_size;
	unsigned long pfn;
	int pagemap_fd;
	int kpageflags_fd;
	bool injection_attempted;
};

FIXTURE_VARIANT(memory_failure)
{
	enum inject_type type;
	int (*inject)(FIXTURE_DATA(memory_failure) * self, void *vaddr);
};

static int madv_hard_inject(FIXTURE_DATA(memory_failure) * self, void *vaddr)
{
	return madvise(vaddr, self->page_size, MADV_HWPOISON);
}

FIXTURE_VARIANT_ADD(memory_failure, madv_hard)
{
	.type = MADV_HARD,
	.inject = madv_hard_inject,
};

static int madv_soft_inject(FIXTURE_DATA(memory_failure) * self, void *vaddr)
{
	return madvise(vaddr, self->page_size, MADV_SOFT_OFFLINE);
}

FIXTURE_VARIANT_ADD(memory_failure, madv_soft)
{
	.type = MADV_SOFT,
	.inject = madv_soft_inject,
};

static void sigbus_action(int signo, siginfo_t *si, void *args)
{
	memcpy(&siginfo, si, sizeof(siginfo_t));
	siglongjmp(signal_jmp_buf, 1);
}

static int setup_sighandler(void)
{
	struct sigaction sa = {
		.sa_sigaction = sigbus_action,
		.sa_flags = SA_SIGINFO,
	};

	return sigaction(SIGBUS, &sa, NULL);
}

FIXTURE_SETUP(memory_failure)
{
	memset(self, 0, sizeof(*self));

	self->page_size = (unsigned long)sysconf(_SC_PAGESIZE);

	memset(&siginfo, 0, sizeof(siginfo));
	if (setup_sighandler())
		SKIP(return, "setup sighandler failed.\n");

	self->pagemap_fd = open(pagemap_proc, O_RDONLY);
	if (self->pagemap_fd == -1)
		SKIP(return, "open %s failed.\n", pagemap_proc);

	self->kpageflags_fd = open(kpageflags_proc, O_RDONLY);
	if (self->kpageflags_fd == -1)
		SKIP(return, "open %s failed.\n", kpageflags_proc);
}

static void teardown_sighandler(void)
{
	struct sigaction sa = {
		.sa_handler = SIG_DFL,
		.sa_flags = SA_SIGINFO,
	};

	sigaction(SIGBUS, &sa, NULL);
}

static void prepare(struct __test_metadata *_metadata, FIXTURE_DATA(memory_failure) * self,
		    void *vaddr)
{
	self->pfn = pagemap_get_pfn(self->pagemap_fd, vaddr);
	ASSERT_NE(self->pfn, -1UL);

	ASSERT_EQ(get_hardware_corrupted_size(&self->corrupted_size), 0);
}

static bool check_memory(void *vaddr, unsigned long size)
{
	char buf[64];

	memset(buf, 0xce, sizeof(buf));
	while (size >= sizeof(buf)) {
		if (memcmp(vaddr, buf, sizeof(buf)))
			return false;
		size -= sizeof(buf);
		vaddr += sizeof(buf);
	}

	return true;
}

static void check(struct __test_metadata *_metadata, FIXTURE_DATA(memory_failure) * self,
		  void *vaddr, enum result_type type, int setjmp)
{
	unsigned long size;
	uint64_t pfn_flags;

	switch (type) {
	case MADV_SOFT_ANON:
	case MADV_HARD_CLEAN_PAGECACHE:
	case MADV_SOFT_CLEAN_PAGECACHE:
	case MADV_SOFT_DIRTY_PAGECACHE:
	case MADV_SOFT_DIRTY_SHMEM:
		/* The page content should remain unchanged. */
		ASSERT_TRUE(check_memory(vaddr, self->page_size));
		/* FALLTHROUGH */
	case MADV_HARD_CLEAN_SHMEM:
	case MADV_SOFT_CLEAN_SHMEM:
		/* It is not expected to receive a SIGBUS signal. */
		ASSERT_EQ(setjmp, 0);

		/* The backing pfn of addr should have changed. */
		ASSERT_NE(pagemap_get_pfn(self->pagemap_fd, vaddr), self->pfn);
		break;
	case MADV_HARD_ANON:
	case MADV_HARD_DIRTY_PAGECACHE:
	case MADV_HARD_DIRTY_SHMEM:
	case READ_ERROR:
		/* The SIGBUS signal should have been received. */
		ASSERT_EQ(setjmp, 1);

		/* Check if siginfo contains correct SIGBUS context. */
		ASSERT_EQ(siginfo.si_signo, SIGBUS);
		ASSERT_EQ(siginfo.si_code, BUS_MCEERR_AR);
		ASSERT_EQ(1UL << siginfo.si_addr_lsb, self->page_size);
		ASSERT_EQ(siginfo.si_addr, vaddr);

		/* XXX Check backing pte is hwpoison entry when supported. */
		ASSERT_TRUE(pagemap_is_swapped(self->pagemap_fd, vaddr));
		break;
	default:
		SKIP(return, "unexpected inject type %d.\n", type);
	}

	/* Check if the value of HardwareCorrupted has increased. */
	ASSERT_EQ(get_hardware_corrupted_size(&size), 0);
	ASSERT_EQ(size, self->corrupted_size + self->page_size / 1024);

	/* Check if HWPoison flag is set. */
	ASSERT_EQ(pageflags_get(self->pfn, self->kpageflags_fd, &pfn_flags), 0);
	ASSERT_EQ(pfn_flags & KPF_HWPOISON, KPF_HWPOISON);
}

static void cleanup(struct __test_metadata *_metadata, FIXTURE_DATA(memory_failure) * self)
{
	unsigned long size;
	uint64_t pfn_flags;

	ASSERT_EQ(unpoison_memory(self->pfn), 0);

	/* Check if HWPoison flag is cleared. */
	ASSERT_EQ(pageflags_get(self->pfn, self->kpageflags_fd, &pfn_flags), 0);
	ASSERT_NE(pfn_flags & KPF_HWPOISON, KPF_HWPOISON);

	/* Check if the value of HardwareCorrupted has decreased. */
	ASSERT_EQ(get_hardware_corrupted_size(&size), 0);
	ASSERT_EQ(size, self->corrupted_size);
}

FIXTURE_TEARDOWN(memory_failure)
{
	/*
	 * Injection may poison the page before failing or delivering SIGBUS, so
	 * clean up after every injection attempt.
	 */
	if (self->injection_attempted)
		cleanup(_metadata, self);

	close(self->kpageflags_fd);
	close(self->pagemap_fd);
	teardown_sighandler();
}

TEST_F(memory_failure, anon)
{
	char *addr;
	int ret;

	addr = mmap(0, self->page_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		SKIP(return, "mmap failed, not enough memory.\n");
	memset(addr, 0xce, self->page_size);

	prepare(_metadata, self, addr);

	ret = sigsetjmp(signal_jmp_buf, 1);
	if (!self->injection_attempted) {
		self->injection_attempted = true;
		ASSERT_EQ(variant->inject(self, addr), 0);
		FORCE_READ(*addr);
	}

	if (variant->type == MADV_HARD)
		check(_metadata, self, addr, MADV_HARD_ANON, ret);
	else
		check(_metadata, self, addr, MADV_SOFT_ANON, ret);

	ASSERT_EQ(munmap(addr, self->page_size), 0);
}

static int prepare_file(const char *fname, unsigned long size)
{
	int fd;
	char *zeros;
	ssize_t written;

	fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, 0664);
	if (fd < 0)
		return fd;

	/*
	 * HPFS cannot grow files with ftruncate(), and OMFS does not support
	 * holes. Write the whole page so OMFS allocates its blocks before
	 * mmap(). A write of only the last byte loses data after eviction.
	 */
	zeros = calloc(size, 1);
	if (!zeros)
		goto failed;
	written = pwrite(fd, zeros, size, 0);
	free(zeros);
	if (written != (ssize_t)size)
		goto failed;
	return fd;
failed:
	close(fd);
	unlink(fname);
	return -1;
}

static int prepare_shmem(const char *fname, unsigned long size)
{
	int fd;

	fd = memfd_create(fname, 0);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, size) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Borrowed from mm/gup_longterm.c. */
static int get_fs_type(int fd)
{
	struct statfs fs;
	int ret;

	do {
		ret = fstatfs(fd, &fs);
	} while (ret && errno == EINTR);

	return ret ? 0 : (int)fs.f_type;
}

/*
 * The page-cache tests need a filesystem which keeps its data on backing
 * store.  When a clean page is poisoned the kernel drops it and the data is
 * read back in.  When a dirty page is poisoned the data is lost, and the
 * kernel records -EIO in the mapping for fsync() to report.
 *
 * tmpfs and ramfs keep their data only in the page cache.  The poisoned
 * page cannot be dropped and read back, and their fsync() does nothing, so
 * neither expectation holds.  hugetlbfs is the same, and it also poisons a
 * whole huge page.  shmem has its own tests below.
 */
static bool fs_has_backing_store(int fs_type)
{
	switch ((unsigned int)fs_type) {
	case 0:
	case TMPFS_MAGIC:
	case RAMFS_MAGIC:
	case HUGETLBFS_MAGIC:
		return false;
	}
	return true;
}

TEST_F(memory_failure, clean_pagecache)
{
	int fd;
	char *addr;
	int ret;
	int fs_type;
	const char *fname = "./clean-page-cache-test-file";

	fd = prepare_file(fname, self->page_size);
	if (fd < 0)
		SKIP(return, "failed to open test file.\n");
	fs_type = get_fs_type(fd);
	if (!fs_has_backing_store(fs_type)) {
		unlink(fname);
		close(fd);
		SKIP(return, "unsupported filesystem :%x\n", fs_type);
	}

	addr = mmap(0, self->page_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		unlink(fname);
		close(fd);
		SKIP(return, "mmap failed, not enough memory.\n");
	}
	memset(addr, 0xce, self->page_size);
	fsync(fd);

	prepare(_metadata, self, addr);

	ret = sigsetjmp(signal_jmp_buf, 1);
	if (!self->injection_attempted) {
		self->injection_attempted = true;
		ASSERT_EQ(variant->inject(self, addr), 0);
		FORCE_READ(*addr);
	}

	if (variant->type == MADV_HARD)
		check(_metadata, self, addr, MADV_HARD_CLEAN_PAGECACHE, ret);
	else
		check(_metadata, self, addr, MADV_SOFT_CLEAN_PAGECACHE, ret);

	ASSERT_EQ(munmap(addr, self->page_size), 0);

	unlink(fname);
	ASSERT_EQ(close(fd), 0);
}

TEST_F(memory_failure, dirty_pagecache)
{
	int fd;
	char *addr;
	int ret;
	int fs_type;
	const char *fname = "./dirty-page-cache-test-file";

	fd = prepare_file(fname, self->page_size);
	if (fd < 0)
		SKIP(return, "failed to open test file.\n");
	fs_type = get_fs_type(fd);
	if (!fs_has_backing_store(fs_type)) {
		unlink(fname);
		close(fd);
		SKIP(return, "unsupported filesystem :%x\n", fs_type);
	}
	/*
	 * nilfs2 does not check the mapping error in nilfs_sync_file().
	 * Remove this skip when its fsync() reports poisoned dirty data.
	 */
	if (fs_type == NILFS_SUPER_MAGIC && variant->type == MADV_HARD) {
		unlink(fname);
		close(fd);
		SKIP(return, "nilfs2 fsync() does not report poisoned dirty data\n");
	}
	/*
	 * ceph_fsync() loses the writeback error recorded for a poisoned
	 * dirty page. Remove this skip when it preserves that error.
	 */
	if (fs_type == CEPH_SUPER_MAGIC && variant->type == MADV_HARD) {
		unlink(fname);
		close(fd);
		SKIP(return, "cephfs fsync() does not report poisoned dirty data\n");
	}

	addr = mmap(0, self->page_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		unlink(fname);
		close(fd);
		SKIP(return, "mmap failed, not enough memory.\n");
	}
	memset(addr, 0xce, self->page_size);

	prepare(_metadata, self, addr);

	ret = sigsetjmp(signal_jmp_buf, 1);
	if (!self->injection_attempted) {
		self->injection_attempted = true;
		ASSERT_EQ(variant->inject(self, addr), 0);
		FORCE_READ(*addr);
	}

	if (variant->type == MADV_HARD)
		check(_metadata, self, addr, MADV_HARD_DIRTY_PAGECACHE, ret);
	else
		check(_metadata, self, addr, MADV_SOFT_DIRTY_PAGECACHE, ret);

	ASSERT_EQ(munmap(addr, self->page_size), 0);

	if (variant->type == MADV_HARD) {
		ASSERT_EQ(fsync(fd), -1);
		ASSERT_EQ(errno, EIO);
		/*
		 * A filesystem which could not remove the poisoned page from
		 * its page cache (FUSE, for one) keeps it until the inode is
		 * evicted, which can be after close() returns.  Remove it now
		 * so that teardown can unpoison the page.
		 */
		ASSERT_EQ(ftruncate(fd, 0), 0);
	}

	/*
	 * OrangeFS writes dirty pages from close(). Unlinking first removes
	 * the server's file handle, so writeback returns -ENOENT and close()
	 * fails. Close while the file is still linked. Remove the name
	 * before checking the result so a failed close cannot leave a file
	 * for the next test.
	 */
	ret = close(fd);
	unlink(fname);
	ASSERT_EQ(ret, 0);
}

TEST_F(memory_failure, dirty_shmem)
{
	int fd;
	char *addr;
	int ret;

	fd = prepare_shmem("shmem-file", self->page_size);
	if (fd < 0)
		SKIP(return, "failed to open test shmem-file.\n");

	addr = mmap(0, self->page_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		SKIP(return, "mmap failed, not enough memory.\n");
	}
	memset(addr, 0xce, self->page_size);

	prepare(_metadata, self, addr);

	ret = sigsetjmp(signal_jmp_buf, 1);
	if (!ret && !self->injection_attempted) {
		self->injection_attempted = true;
		ASSERT_EQ(variant->inject(self, addr), 0);
	}

	if (variant->type == MADV_HARD) {
		check(_metadata, self, addr, MADV_HARD_DIRTY_SHMEM, ret);
		ret = sigsetjmp(signal_jmp_buf, 1);
		if (ret == 0)
			FORCE_READ(*addr);
		check(_metadata, self, addr, READ_ERROR, ret);
	} else {
		check(_metadata, self, addr, MADV_SOFT_DIRTY_SHMEM, ret);
	}

	ASSERT_EQ(munmap(addr, self->page_size), 0);

	ASSERT_EQ(close(fd), 0);
}

TEST_F(memory_failure, clean_shmem)
{
	int fd;
	char *addr;
	int ret;

	fd = prepare_shmem("shmem-file", self->page_size);
	if (fd < 0)
		SKIP(return, "failed to open test shmem-file.\n");

	addr = mmap(0, self->page_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		SKIP(return, "mmap failed, not enough memory.\n");
	}
	FORCE_READ(*addr);

	prepare(_metadata, self, addr);

	ret = sigsetjmp(signal_jmp_buf, 1);
	if (!ret && !self->injection_attempted) {
		self->injection_attempted = true;
		ASSERT_EQ(variant->inject(self, addr), 0);
	}

	if (variant->type == MADV_HARD) {
		check(_metadata, self, addr, MADV_HARD_CLEAN_SHMEM, ret);
		ret = sigsetjmp(signal_jmp_buf, 1);
		if (ret == 0)
			FORCE_READ(*addr);
		check(_metadata, self, addr, READ_ERROR, ret);
	} else {
		/* Test the address accessability without check_memory(). */
		FORCE_READ(*addr);
		check(_metadata, self, addr, MADV_SOFT_CLEAN_SHMEM, ret);
	}

	ASSERT_EQ(munmap(addr, self->page_size), 0);

	ASSERT_EQ(close(fd), 0);
}

TEST_HARNESS_MAIN
