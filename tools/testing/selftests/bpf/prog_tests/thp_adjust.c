// SPDX-License-Identifier: GPL-2.0

#include <sys/mman.h>
#include <test_progs.h>
#include "test_thp_adjust.skel.h"

#define LEN (4 * 1024 * 1024) /* 4MB */
#define THP_ENABLED_PATH "/sys/kernel/mm/transparent_hugepage/enabled"
#define SMAPS_PATH "/proc/self/smaps"
#define ANON_HUGE_PAGES "AnonHugePages:"

static bool need_reset;
static char *thp_addr;

int parse_thp_setting(const char *buf)
{
	const char *start = strchr(buf, '[');
	const char *end = start ? strchr(start, ']') : NULL;
	char setting[32] = {0};
	size_t len;

	if (!start || !end || end <= start)
		return -1;

	len = end - start - 1;
	if (len >= sizeof(setting))
		len = sizeof(setting) - 1;

	strncpy(setting, start + 1, len);
	setting[len] = '\0';

	if (strcmp(setting, "madvise") == 0 || strcmp(setting, "always") == 0)
		return 0;
	return 1;
}

int thp_set(void)
{
	const char *desired_value = "madvise";
	char buf[32] = {0};
	int fd, err;

	fd = open(THP_ENABLED_PATH, O_RDWR);
	if (fd == -1)
		return -1;

	err = read(fd, buf, sizeof(buf) - 1);
	if (err == -1)
		goto close_fd;

	err = parse_thp_setting(buf);
	if (err == -1 || err == 0)
		goto close_fd;

	err = lseek(fd, 0, SEEK_SET);
	if (err == -1)
		goto close_fd;

	err = write(fd, desired_value, strlen(desired_value));
	if (err == -1)
		goto close_fd;
	need_reset = true;

close_fd:
	close(fd);
	return err;
}

int thp_reset(void)
{
	int fd, err;

	if (!need_reset)
		return 0;

	fd = open(THP_ENABLED_PATH, O_WRONLY);
	if (fd == -1)
		return -1;

	err = write(fd, "never", strlen("never"));
	close(fd);
	return err;
}

int thp_alloc(void)
{
	int err, i;

	thp_addr = mmap(NULL, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (thp_addr == MAP_FAILED)
		return -1;

	err = madvise(thp_addr, LEN, MADV_HUGEPAGE);
	if (err == -1)
		goto unmap;

	for (i = 0; i < LEN; i += 4096)
		thp_addr[i] = 1;
	return 0;

unmap:
	munmap(thp_addr, LEN);
	return -1;
}

void thp_free(void)
{
	if (!thp_addr)
		return;
	munmap(thp_addr, LEN);
}

int thp_size(void)
{
	unsigned long total_kb = 0;
	char *line, *saveptr;
	ssize_t bytes_read;
	char buf[4096];
	int fd;

	fd = open(SMAPS_PATH, O_RDONLY);
	if (fd == -1)
		return -1;

	while ((bytes_read = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[bytes_read] = '\0';
		line = strtok_r(buf, "\n", &saveptr);
		while (line) {
			if (strstr(line, ANON_HUGE_PAGES)) {
				unsigned long kb;

				if (sscanf(line + strlen(ANON_HUGE_PAGES), "%lu", &kb) == 1)
					total_kb += kb;
			}
			line = strtok_r(NULL, "\n", &saveptr);
		}
	}

	if (bytes_read == -1)
		total_kb = -1;

	close(fd);
	return total_kb;
}

void test_thp_adjust(void)
{
	struct test_thp_adjust *skel;
	int err;

	skel = test_thp_adjust__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	skel->bss->target_pid = getpid();

	err = test_thp_adjust__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto destroy;

	err = test_thp_adjust__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto destroy;

	if (!ASSERT_NEQ(thp_set(), -1, "THP set"))
		goto destroy;
	if (!ASSERT_NEQ(thp_alloc(), -1, "THP alloc"))
		goto thp_reset;
	ASSERT_EQ(thp_size(), 0, "THP size");
	thp_free();

thp_reset:
	ASSERT_NEQ(thp_reset(), -1, "THP reset");
destroy:
	test_thp_adjust__destroy(skel);
}
