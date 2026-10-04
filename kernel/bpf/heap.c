// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf_verifier.h>

/* Indexes for binary tree encoded as an array */
static inline int left_child(int i) { return 2 * i + 1; }
static inline int right_child(int i) { return 2 * i + 2; }
static inline int parent(int i) { return (i - 1) / 2; }

static inline int greater(struct bpf_min_heap *heap, int a, int b)
{
	return heap->compare(a, b, heap->arg) > 0;
}

void bpf_min_heap_init(struct bpf_min_heap *heap, int (*compare)(int, int, void *), void *arg)
{
	memset(heap, 0, sizeof(*heap));
	heap->compare = compare;
	heap->arg = arg;
}

void bpf_min_heap_free(struct bpf_min_heap *heap)
{
	kfree(heap->elements);
	heap->elements = NULL;
	heap->capacity = 0;
	heap->count = 0;
}

int bpf_min_heap_push(struct bpf_min_heap *heap, int elt)
{
	int new_capacity, i;
	int *elements;
	void *tmp;

	if (heap->count == heap->capacity) {
		new_capacity = heap->capacity ? heap->capacity * 2 : 16;
		tmp = krealloc(heap->elements,
			       sizeof(*heap->elements) * new_capacity,
			       GFP_KERNEL_ACCOUNT);
		if (!tmp)
			return -ENOMEM;
		heap->elements = tmp;
		heap->capacity = new_capacity;
	}

	elements = heap->elements;
	i = heap->count;
	elements[i] = elt;
	heap->count++;
	while (i != 0 && greater(heap, elements[parent(i)], elements[i])) {
		swap(elements[i], elements[parent(i)]);
		i = parent(i);
	}
	return 0;
}

static inline void sink_root(struct bpf_min_heap *heap)
{
	int *elements = heap->elements;
	int i = 0;

	while ((left_child(i)  < heap->count && greater(heap, elements[i], elements[left_child(i)])) ||
	       (right_child(i) < heap->count && greater(heap, elements[i], elements[right_child(i)]))) {
		if (right_child(i) >= heap->count || greater(heap, elements[right_child(i)], elements[left_child(i)])) {
			swap(elements[i], elements[left_child(i)]);
			i = left_child(i);
		} else {
			swap(elements[i], elements[right_child(i)]);
			i = right_child(i);
		}
	}
}

bool bpf_min_heap_pop(struct bpf_min_heap *heap, int *elt)
{
	if (heap->count == 0)
		return false;

	int *elements = heap->elements;
	*elt = elements[0];
	elements[0] = elements[heap->count - 1];
	--heap->count;
	sink_root(heap);
	return true;
}
