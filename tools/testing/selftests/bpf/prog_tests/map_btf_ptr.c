#include <test_progs.h>

#include "map_btf_ptr.skel.h"

void test_map_btf_ptr(void)
{
	struct map_btf_ptr *skel;

	skel = map_btf_ptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "map_btf_ptr__open_and_load"))
		return;
	map_btf_ptr__destroy(skel);
}
