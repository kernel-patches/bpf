// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <test_progs.h>
#include "trace_helpers.h"
#include "test_spin.skel.h"

void test_spin(void)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *links[20];
	long key, next_key, value;
	struct bpf_program *prog;
	struct test_spin *skel;
	int map_fd, i, j = 0;
	const char *section;
	struct ksym *sym;
	char symbol[256];
	int err;

	err = load_kallsyms();
	if (!ASSERT_OK(err, "load_kallsyms"))
		return;
	skel = test_spin__open_and_load();

	if (!ASSERT_OK_PTR(skel, "test_spin__open_and_load"))
		return;

	map_fd = bpf_map__fd(skel->maps.my_map);

	bpf_object__for_each_program(prog, skel->obj) {
		section = bpf_program__section_name(prog);
		if (sscanf(section, "kprobe/%s", symbol) != 1)
			continue;

		/* Attach prog only when symbol exists */
		if (ksym_get_addr(symbol)) {
			links[j] = bpf_program__attach(prog);
			err = libbpf_get_error(links[j]);
			if (!ASSERT_OK(err, "bpf_program__attach")) {
				fprintf(stderr, "bpf_program__attach failed\n");
				links[j] = NULL;
				goto cleanup;
			}
			j++;
		}
	}

	for (i = 0; i < 5; i++) {
		key = 0;
		printf("kprobing funcs:");
		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(map_fd, &next_key, &value);
			assert(next_key == value);
			sym = ksym_search(value);
			key = next_key;
			if (!sym) {
				printf("ksym not found. Is kallsyms loaded?\n");
				continue;
			}

			printf(" %s", sym->name);
		}
		if (key)
			printf("\n");
		key = 0;
		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
			bpf_map_delete_elem(map_fd, &next_key);
		sleep(1);
	}

cleanup:
	for (j--; j >= 0; j--)
		bpf_link__destroy(links[j]);

	bpf_object__close(obj);
}
