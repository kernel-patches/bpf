// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#ifdef __x86_64__

#define _GNU_SOURCE
#include <unistd.h>
#include "sdt.h"
#include "uprobe_optimized.skel.h"

#define TRAMP "[uprobes-trampoline]"

static unsigned char nop5[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };

noinline void uprobe_test(void)
{
	asm volatile ("					\n"
		".global uprobe_test_nop5		\n"
		".type uprobe_test_nop5, STT_FUNC	\n"
		"uprobe_test_nop5:			\n"
		".byte 0x0f, 0x1f, 0x44, 0x00, 0x00	\n"
	);
}

extern u8 uprobe_test_nop5[];

noinline void usdt_test(void)
{
	STAP_PROBE(optimized_uprobe, usdt);
}

static void *find_nop5(void *fn)
{
	int i;

	for (i = 0; i < 10; i++) {
		if (!memcmp(nop5, fn + i, 5))
			return fn + i;
	}
	return NULL;
}

static int find_uprobes_trampoline(void **start, void **end)
{
	char line[128];
	int ret = -1;
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		fprintf(stderr, "cannot open maps\n");
		return -1;
	}

	while (fgets(line, sizeof(line), maps)) {
		int m = -1;

		/* We care only about private r-x mappings. */
		if (sscanf(line, "%p-%p r-xp %*x %*x:%*x %*u %n", start, end, &m) != 2)
			continue;
		if (m < 0)
			continue;
		if (!strncmp(&line[m], TRAMP, sizeof(TRAMP)-1)) {
			ret = 0;
			break;
		}
	}

	fclose(maps);
	return ret;
}

static void check_attach(struct uprobe_optimized *skel, void (*trigger)(void), void *addr)
{
	void *tramp_start, *tramp_end;
	struct __arch_relative_insn {
		u8 op;
		s32 raddr;
	} __packed *call;

	s32 delta;

	/* Uprobe gets optimized after first trigger, so let's press twice. */
	trigger();
	trigger();

	if (!ASSERT_OK(find_uprobes_trampoline(&tramp_start, &tramp_end), "uprobes_trampoline"))
		return;

	/* Make sure bpf program got executed.. */
	ASSERT_EQ(skel->bss->executed, 2, "executed");

	/* .. and check the trampoline is as expected. */
	call = (struct __arch_relative_insn *) addr;
	delta = (unsigned long) tramp_start - ((unsigned long) addr + 5);

	ASSERT_EQ(call->op, 0xe8, "call");
	ASSERT_EQ(call->raddr, delta, "delta");
	ASSERT_EQ(tramp_end - tramp_start, 4096, "size");
}

static void check_detach(struct uprobe_optimized *skel, void (*trigger)(void), void *addr)
{
	void *tramp_start, *tramp_end;

	/* [uprobes_trampoline] stays after detach */
	ASSERT_OK(find_uprobes_trampoline(&tramp_start, &tramp_end), "uprobes_trampoline");
	ASSERT_OK(memcmp(addr, nop5, 5), "nop5");
}

static void check(struct uprobe_optimized *skel, struct bpf_link *link,
		  void (*trigger)(void), void *addr)
{
	check_attach(skel, trigger, addr);
	bpf_link__destroy(link);
	check_detach(skel, trigger, addr);
}

static void test_uprobe(void)
{
	struct uprobe_optimized *skel;
	struct bpf_link *link;
	unsigned long offset;

	skel = uprobe_optimized__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_optimized__open_and_load"))
		return;

	offset = get_uprobe_offset(&uprobe_test_nop5);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		goto cleanup;

	link = bpf_program__attach_uprobe_opts(skel->progs.test_1,
				0, "/proc/self/exe", offset, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_opts"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test_nop5);

cleanup:
	uprobe_optimized__destroy(skel);
}

static void test_uprobe_multi(void)
{
	struct uprobe_optimized *skel;
	struct bpf_link *link;

	skel = uprobe_optimized__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_optimized__open_and_load"))
		return;

	link = bpf_program__attach_uprobe_multi(skel->progs.test_2,
				0, "/proc/self/exe", "uprobe_test_nop5", NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test_nop5);

cleanup:
	uprobe_optimized__destroy(skel);
}

static void test_usdt(void)
{
	struct uprobe_optimized *skel;
	struct bpf_link *link;
	void *addr;

	errno = 0;
	addr = find_nop5(usdt_test);
	if (!ASSERT_OK_PTR(addr, "find_nop5"))
		return;

	skel = uprobe_optimized__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_optimized__open_and_load"))
		return;

	link = bpf_program__attach_usdt(skel->progs.test_3,
				-1 /* all PIDs */, "/proc/self/exe",
				"optimized_uprobe", "usdt", NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_usdt"))
		goto cleanup;

	check(skel, link, usdt_test, addr);

cleanup:
	uprobe_optimized__destroy(skel);
}

static bool race_stop;

static void *worker_trigger(void *arg)
{
	unsigned long rounds = 0;

	while (!race_stop) {
		uprobe_test();
		rounds++;
	}

	printf("tid %d trigger rounds: %lu\n", gettid(), rounds);
	return NULL;
}

static void *worker_attach(void *arg)
{
	struct uprobe_optimized *skel;
	unsigned long rounds = 0;

	skel = uprobe_optimized__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_optimized__open_and_load"))
		goto cleanup;

	while (!race_stop) {
		skel->links.test_2 = bpf_program__attach_uprobe_multi(skel->progs.test_2, -1,
						"/proc/self/exe", "uprobe_test_nop5", NULL);
		if (!ASSERT_OK_PTR(skel->links.test_2, "bpf_program__attach_uprobe_multi"))
			break;
		bpf_link__destroy(skel->links.test_2);
		skel->links.test_2 = NULL;
		rounds++;
	}

	printf("tid %d attach rounds: %lu hits: %lu\n", gettid(), rounds, skel->bss->executed);

cleanup:
	uprobe_optimized__destroy(skel);
	return NULL;
}

static void test_race(void)
{
	int err, i, nr_cpus, nr;
	pthread_t *threads;

        nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GE(nr_cpus, 0, "nr_cpus"))
		return;

	nr = nr_cpus * 2;
	threads = malloc(sizeof(*threads) * nr);
	if (!ASSERT_OK_PTR(threads, "malloc"))
		return;

	for (i = 0; i < nr_cpus; i++) {
		err = pthread_create(&threads[i], NULL, worker_trigger, NULL);
		if (!ASSERT_OK(err, "pthread_create"))
			goto cleanup;
	}

	for (; i < nr; i++) {
		err = pthread_create(&threads[i], NULL, worker_attach, NULL);
		if (!ASSERT_OK(err, "pthread_create"))
			goto cleanup;
	}

	sleep(4);

cleanup:
	race_stop = true;
	for (i = 0; i < nr; i++)
		pthread_join(threads[i], NULL);
}

static void test_optimized(void)
{
	if (test__start_subtest("uprobe"))
		test_uprobe();
	if (test__start_subtest("uprobe_multi"))
		test_uprobe_multi();
	if (test__start_subtest("usdt"))
		test_usdt();
	if (test__start_subtest("race"))
		test_race();
}
#else
static void test_optimized(void)
{
	test__skip();
}
#endif /* __x86_64__ */

void test_uprobe_optimized(void)
{
	test_optimized();
}
