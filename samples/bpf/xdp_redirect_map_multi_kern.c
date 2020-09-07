/* SPDX-License-Identifier: GPL-2.0
 *
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 256);
} forward_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} rxcnt SEC(".maps");

SEC("xdp_redirect_map_multi")
int xdp_redirect_map_multi_prog(struct xdp_md *ctx)
{
	long *value;
	u32 key = 0;

	/* count packet in global counter */
	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (value)
		*value += 1;

	return bpf_redirect_map_multi(&forward_map, NULL, BPF_F_EXCLUDE_INGRESS);
}

char _license[] SEC("license") = "GPL";
