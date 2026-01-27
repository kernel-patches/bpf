#pragma once

#ifdef __BPF__

u64 bump_alloc_internal(size_t bytes, size_t alignment);
#define bump_alloc(bytes, alignment) ((void __arena *)bump_alloc_internal((bytes), (alignment)))
int bump_init(size_t contig_pages);
int bump_destroy(void);
int bump_memlimit(u64 lim_memusage);

#endif /* __BPF__ */

#define BUMP_ALLOCS_MAX (64)

struct bump {
	size_t max_contig_bytes;
	void __arena *memory;
	size_t off;
	size_t lim_memusage;
	size_t cur_memusage;

	void __arena *past_allocs[BUMP_ALLOCS_MAX];

	size_t past_allocs_ind;
};

