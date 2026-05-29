// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 256);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

void __arena *bpf_arena_alloc(void *map, __u32 size) __ksym __weak;
void bpf_arena_free(void *map, void __arena *ptr) __ksym __weak;
void bpf_preempt_disable(void) __ksym;
void bpf_preempt_enable(void) __ksym;

#define OBJ_SIZE 4096
#define FREEPTR_OFFSET (OBJ_SIZE / 2)
#define SHEAF_FILL 4
#define TARGET_IDX SHEAF_FILL
#define EXTRA_IDX (TARGET_IDX + 1)
#define NR_OBJS (EXTRA_IDX + 1)

int alloc_failed;
int drain_failed;
int cycle_alloc_failed;
int cycle_alloc_mismatch;
int stale_alloc_null;
int done;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
static __u8 __arena *objs[NR_OBJS];
#endif

SEC("syscall")
int arena_slab_freeptr_stale_pcs(void *ctx)
{
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
	__u8 __arena *victim, *p;
	__u64 raw;
	int i;

	for (i = 0; i < NR_OBJS; i++) {
		objs[i] = bpf_arena_alloc(&arena, OBJ_SIZE);
		if (!objs[i]) {
			alloc_failed = i + 1;
			return 0;
		}
		objs[i][0] = i + 1;
	}

	bpf_preempt_disable();

	/* Fill the per-cpu sheaf so the next free reaches SLUB proper. */
	for (i = 1; i <= SHEAF_FILL; i++)
		bpf_arena_free(&arena, objs[i - 1]);

	victim = objs[TARGET_IDX];

	/*
	 * The 4096-byte bucket has one object per slab and a 4-object sheaf.
	 * Free @victim while the sheaf is full, then turn its encoded NULL
	 * freepointer into any non-NULL decoded value. The arena clamp keeps
	 * non-NULL decoded values in the same slab and object-aligned, so this
	 * becomes a freelist self-cycle back to @victim.
	 */
	bpf_arena_free(&arena, victim);
	raw = *(__u64 __arena *)(victim + FREEPTR_OFFSET);
	*(__u64 __arena *)(victim + FREEPTR_OFFSET) = raw ^ 1;

	for (i = 0; i < SHEAF_FILL; i++) {
		p = bpf_arena_alloc(&arena, OBJ_SIZE);
		if (!p) {
			drain_failed = i + 1;
			goto out;
		}
	}

	p = bpf_arena_alloc(&arena, OBJ_SIZE);
	if (!p) {
		cycle_alloc_failed = 1;
		goto out;
	}
	if (p != victim)
		cycle_alloc_mismatch = 1;

	for (i = 0; i < SHEAF_FILL; i++)
		bpf_arena_free(&arena, victim);

	/*
	 * The sheaf is full of duplicate victim pointers now. Free the four
	 * filler objects plus one extra object directly to SLUB, leaving enough
	 * partial slabs that the next target-slab zero-inuse transition discards
	 * the target page instead of keeping it on the partial list.
	 */
	for (i = 0; i < SHEAF_FILL; i++)
		bpf_arena_free(&arena, objs[i]);
	bpf_arena_free(&arena, objs[EXTRA_IDX]);

	bpf_arena_free(&arena, victim);

	p = bpf_arena_alloc(&arena, OBJ_SIZE);
	if (!p)
		stale_alloc_null = 1;

	done = 1;
out:
	bpf_preempt_enable();
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
