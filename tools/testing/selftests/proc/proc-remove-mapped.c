// SPDX-License-Identifier: GPL-2.0
/*
 * Removing a /proc entry with a mapped file open must not wait for that file
 * and must leave the file dead. Map a memory BAR of a PCI device through
 * /proc/bus/pci and remove the device, which removes its entry. Nothing here
 * can know which device is safe to remove and rescan, so it is named in
 * PROC_PCI_DEV, e.g. PROC_PCI_DEV=0000:00:03.0.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/pci.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define DEV_ENV		"PROC_PCI_DEV"
#define SYSFS_DEVICES	"/sys/bus/pci/devices/"
#define SYSFS_RESCAN	"/sys/bus/pci/rescan"
#define PROC_PCI	"/proc/bus/pci/"
#define IORESOURCE_MEM	0x00000200

static sigjmp_buf fault;

static void on_sigbus(int sig)
{
	siglongjmp(fault, 1);
}

/* the first memory BAR of @dev */
static int mem_bar(const char *dev, unsigned long long *start)
{
	unsigned long long s, e, flags;
	char path[PATH_MAX];
	int ret = -ENODEV;
	FILE *f;

	snprintf(path, sizeof(path), SYSFS_DEVICES "%s/resource", dev);
	f = fopen(path, "r");
	if (!f)
		return -errno;
	while (fscanf(f, "%llx %llx %llx", &s, &e, &flags) == 3) {
		if ((flags & IORESOURCE_MEM) && e >= s) {
			*start = s;
			ret = 0;
			break;
		}
	}
	fclose(f);
	return ret;
}

static int write_one(const char *path)
{
	int fd, ret;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = write(fd, "1", 1) < 0 ? -errno : 0;
	close(fd);
	return ret;
}

FIXTURE(pci) {
	char dev[16];
	char path[64];
	bool removed;
};

FIXTURE_SETUP(pci)
{
	const char *dev = getenv(DEV_ENV);

	self->removed = false;
	if (!dev)
		SKIP(return, DEV_ENV " isn't set");
	/* 0000:BB:DD.F is /proc/bus/pci/BB/DD.F */
	if (strlen(dev) != 12 || strncmp(dev, "0000:", 5))
		SKIP(return, "%s: not a device in PCI domain 0", dev);
	strcpy(self->dev, dev);
	snprintf(self->path, sizeof(self->path), PROC_PCI "%.2s/%s",
		 dev + 5, dev + 8);
	if (access(self->path, R_OK))
		SKIP(return, "%s: %s", self->path, strerror(errno));
}

FIXTURE_TEARDOWN(pci)
{
	if (self->removed && write_one(SYSFS_RESCAN))
		TH_LOG("couldn't rescan the PCI bus for %s", self->dev);
}

TEST_F(pci, remove_while_mapped)
{
	long psz = sysconf(_SC_PAGESIZE);
	unsigned long long start = 0;
	char path[PATH_MAX];
	volatile unsigned int *p;
	unsigned int v;
	int fd;

	if (mem_bar(self->dev, &start))
		SKIP(return, "%s has no memory BAR", self->dev);

	fd = open(self->path, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	if (ioctl(fd, PCIIOC_MMAP_IS_MEM)) {
		/* no PCI mmap on this architecture, or locked down */
		if (errno == EINVAL || errno == EPERM) {
			close(fd);
			SKIP(return, "PCIIOC_MMAP_IS_MEM: %s", strerror(errno));
		}
		ASSERT_TRUE(false) {
			TH_LOG("PCIIOC_MMAP_IS_MEM: %s", strerror(errno));
		}
	}
	p = mmap(NULL, psz, PROT_READ, MAP_SHARED, fd, start);
	if (p == MAP_FAILED)
		SKIP(return, "mmap: %s", strerror(errno));

	/* The BAR can be read while the device is there. */
	ASSERT_NE(signal(SIGBUS, on_sigbus), SIG_ERR);
	if (sigsetjmp(fault, 1) == 0) {
		v = *p;
	} else {
		ASSERT_TRUE(false) {
			TH_LOG("reading the mapping faulted before the removal");
		}
	}

	/* Removing the device removes its entry. */
	snprintf(path, sizeof(path), SYSFS_DEVICES "%s/remove", self->dev);
	ASSERT_EQ(write_one(path), 0);
	self->removed = true;
	EXPECT_EQ(access(self->path, F_OK), -1);

	/*
	 * The file is dead. The mapping isn't procfs's to unmap, it lives in
	 * the iomem address space of /dev/mem, see proc_bus_pci_open(), and
	 * is left alone like a sysfs resource file's.
	 */
	EXPECT_EQ(pread(fd, &v, sizeof(v), 0), -1);
	EXPECT_EQ(errno, EIO);

	munmap((void *)p, psz);
	close(fd);
}

TEST_HARNESS_MAIN
