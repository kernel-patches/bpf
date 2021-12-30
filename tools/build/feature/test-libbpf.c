// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>

int main(void)
{
	return bpf_object__open_file("test", NULL) ? 0 : -1;
}
