// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <linux/compiler.h>
#include <linux/bpf.h>
#include <sys/sysinfo.h>
#include <test_progs.h>
#include <sched.h>

#include "test_relay_map.lskel.h"

static int duration;

/* file names in debugfs */
static const char dirname[]		= "relay_map_selftest";
static const char mapname[]		= "relay_map";
static const char mapname_ow[]	= "relay_map_ow";
struct relay_sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

static int sample_cnt;
static int overwrite;

static void process_sample(struct relay_sample *s)
{
	++sample_cnt;

	switch (s->seq) {
	case 0:
		/* sample1 will not appear in overwrite mode */
		CHECK(overwrite != 0, "overwrite_mode",
		      "sample1 appears in overwrite mode\n");
		CHECK(s->value != 333, "sample1_value", "exp %ld, got %ld\n",
		      333L, s->value);
		break;
	case 1:
		CHECK(s->value != 777, "sample2_value", "exp %ld, got %ld\n",
		      777L, s->value);
		break;
	default:
		break;
	}
}

static int relaymap_read(const char *mapname)
{
	int cpu = libbpf_num_possible_cpus();
	char name[NAME_MAX];
	struct relay_sample data;
	int maxloop;
	FILE *fp;

	for (int i = 0; i < cpu; ++i) {
		sprintf(name, "/sys/kernel/debug/%s/%s%d", dirname, mapname, i);
		fp = fopen(name, "r");
		if (CHECK(!fp, "fopen", "relay file open failed\n"))
			return -1;

		maxloop = 0;
		while (fread(&data, sizeof(data), 1, fp)) {
			process_sample(&data);

			/* just 2 samples output */
			if (++maxloop > 2)
				return -1;
		}
	}
	return 0;
}

static struct test_relay_map_lskel *skel;

static void trigger_samples(void)
{
	skel->bss->dropped = 0;
	skel->bss->total = 0;
	skel->bss->seq = 0;

	/* trigger exactly two samples */
	skel->bss->value = 333;
	syscall(__NR_getpgid);
	skel->bss->value = 777;
	syscall(__NR_getpgid);
}

static void relaymap_subtest(void)
{
	int err, map_fd;

	skel = test_relay_map_lskel__open();
	if (CHECK(!skel, "skel_open", "skeleton open failed\n"))
		return;

	/* setup relay param */
	skel->maps.relay_map.max_entries = 1024;

	err = test_relay_map_lskel__load(skel);
	if (CHECK(err, "skel_load", "skeleton load failed\n"))
		goto cleanup;

	/* only trigger BPF program for current process */
	skel->bss->pid = getpid();

	/* turn off overwrite */
	skel->bss->overwrite_enable = 0;
	overwrite = skel->bss->overwrite_enable;

	err = test_relay_map_lskel__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attachment failed: %d\n", err))
		goto cleanup;

	/* before file setup - output failed */
	trigger_samples();
	CHECK(skel->bss->dropped != 2, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);

	/* after file setup - output succ */
	map_fd = skel->maps.relay_map.map_fd;
	err = bpf_map_update_elem(map_fd, NULL, dirname, 0);
	if (CHECK(err, "map_update", "map update failed: %d\n", err))
		goto cleanup;
	trigger_samples();
	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);

	sample_cnt = 0;
	err = relaymap_read(mapname);
	CHECK(sample_cnt != 2, "sample_cnt", "exp %d samples, got %d\n",
		   2, sample_cnt);

	test_relay_map_lskel__detach(skel);
cleanup:
	test_relay_map_lskel__destroy(skel);
}

static void relaymap_overwrite_subtest(void)
{
	int err, map_fd;

	skel = test_relay_map_lskel__open();
	if (CHECK(!skel, "skel_open", "skeleton open failed\n"))
		return;

	/* To test overwrite mode, we create subbuf of one-sample size */
	skel->maps.relay_map_ow.max_entries = sizeof(struct relay_sample);

	err = test_relay_map_lskel__load(skel);
	if (CHECK(err, "skel_load", "skeleton load failed\n"))
		goto cleanup;

	/* only trigger BPF program for current process */
	skel->bss->pid = getpid();

	/* turn on overwrite */
	skel->bss->overwrite_enable = 1;
	overwrite = skel->bss->overwrite_enable;

	err = test_relay_map_lskel__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attachment failed: %d\n", err))
		goto cleanup;

	map_fd = skel->maps.relay_map_ow.map_fd;
	err = bpf_map_update_elem(map_fd, NULL, dirname, 0);
	if (CHECK(err, "map_update", "map update failed: %d\n", err))
		goto cleanup;
	trigger_samples();
	/* relay_write never fails whether overwriting or not */
	CHECK(skel->bss->dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, skel->bss->dropped);
	CHECK(skel->bss->total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, skel->bss->total);

	/* 2 samples are output, but only the last (val=777) could be seen */
	sample_cnt = 0;
	err = relaymap_read(mapname_ow);
	CHECK(sample_cnt != 1, "sample_cnt", "exp %d samples, got %d\n",
		   1, sample_cnt);

	test_relay_map_lskel__detach(skel);
cleanup:
	test_relay_map_lskel__destroy(skel);
}

void test_relaymap(void)
{
	if (test__start_subtest("relaymap"))
		relaymap_subtest();
	if (test__start_subtest("relaymap_overwrite"))
		relaymap_overwrite_subtest();
}
