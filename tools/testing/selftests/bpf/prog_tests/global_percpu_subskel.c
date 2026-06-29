// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "test_global_percpu_data.subskel.h"

void test_global_percpu_data_subskel(void)
{
	struct test_global_percpu_data *subskel = NULL;
	struct bpf_object *obj;
	int i;

	obj = bpf_object__open_file("./test_global_percpu_data.bpf.o", NULL);
	if (!ASSERT_OK_PTR(obj, "bpf_object__open_file"))
		return;

	subskel = test_global_percpu_data__open(obj);
	if (!ASSERT_OK_PTR(subskel, "test_global_percpu_data__open"))
		goto out;

	if (!ASSERT_OK_PTR(subskel->subskel, "subskel"))
		goto out;
	if (!ASSERT_OK_PTR(subskel->maps.percpu, "maps.percpu"))
		goto out;
	ASSERT_EQ(bpf_map__type(subskel->maps.percpu), BPF_MAP_TYPE_PERCPU_ARRAY,
		  "percpu_map_type");
	ASSERT_GT(subskel->subskel->var_cnt, 0, "var_cnt");

	for (i = 0; i < subskel->subskel->var_cnt; i++) {
		const struct bpf_var_skeleton *var;

		var = (void *) subskel->subskel->vars + i * subskel->subskel->var_skel_sz;
		ASSERT_NEQ(var->map, &subskel->maps.percpu, "var");
	}

out:
	test_global_percpu_data__destroy(subskel);
	bpf_object__close(obj);
}
