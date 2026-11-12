// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tag the functions which fmod_ret programs can attach to, because they return
 * errors: "bpf_fmodret_retval:-22,-12". fmodret_scan.c finds the errors in the
 * machine code. This file decides which functions it looks at, and which of the
 * errors count.
 *
 * A program skips the function. That is not a failure of the function if it
 * works on an object of its caller before it returns the error: it unlocks,
 * frees or initializes it. Such an error does not count, see set_protos().
 *
 * Whether ftrace can attach a program to the function is not looked at: as for
 * fentry, that is found out when it is tried.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>

#include "fmodret.h"
#include "fmodret_scan.h"
#include "image.h"

#define TAG	"bpf_fmodret_retval:"

/* Return the size of the integer which FUNC returns, or 0 */
static __u32 int_return_size(const struct btf *btf, const struct btf_type *func)
{
	const struct btf_type *t = btf__type_by_id(btf, func->type);
	int ret = t->type ? btf__resolve_type(btf, t->type) : -1;

	if (ret < 0)
		return 0;
	t = btf__type_by_id(btf, ret);
	return btf_is_int(t) || btf_is_any_enum(t) ? t->size : 0;
}

/*
 * The codes of include/linux/errno.h, 512 and up, never reach user space. They,
 * -EAGAIN, -EMSGSIZE and -EINPROGRESS tell the caller to retry, to go on or to
 * wait, not that the function failed.
 */
static bool means_failure(int error)
{
	return error > -512 && error != -EAGAIN && error != -EMSGSIZE && error != -EINPROGRESS;
}

static int cmp_error(const void *va, const void *vb)
{
	return *(const int *)va - *(const int *)vb;
}

/*
 * Write the tag for a function which returns SIZE bytes, and in them one of the
 * NR VALUES of the return value register. In 8 bytes an error is sign extended.
 * Return false if there is nothing to tag.
 *
 * The machine code cannot tell the -EPERM of a permission check from the -1 of a
 * comparator or of "no such index": a function whose only error is -1 has none.
 */
static bool format_tag(char *tag, const int64_t *values, size_t nr, __u32 size)
{
	size_t i, n = 0;
	int errors[nr];

	for (i = 0; i < nr; i++) {
		int error = values[i];

		if ((size == 4 || values[i] == error) && means_failure(error))
			errors[n++] = error;
	}
	qsort(errors, n, sizeof(*errors), cmp_error);
	tag += sprintf(tag, TAG);
	for (i = 0; i < n; i++)
		if (!i || errors[i] != errors[i - 1])
			tag += sprintf(tag, "%s%d", i ? "," : "", errors[i]);
	return n && errors[0] < -1;
}

/*
 * Tell SCAN what BTF says about the functions of IMG. A function which returns
 * nothing cannot fail: what it does to an object is done when its caller returns
 * an error. Unlock, put, free and init functions are of this kind. A function
 * which returns a value may have failed, and that may be the reason for the error.
 */
static void set_protos(struct scan *scan, const struct image *img, const struct btf *btf)
{
	__u32 id, nr_types = btf__type_cnt(btf);

	for (id = 1; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		const struct image_func *func = NULL;
		unsigned int pointers = 0, i;

		if (btf_is_func(t))
			func = image_func(img, btf__name_by_offset(btf, t->name_off));
		if (!func)
			continue;
		t = btf__type_by_id(btf, t->type);
		for (i = 0; i < btf_vlen(t) && i < 32; i++) {
			int type = btf__resolve_type(btf, btf_params(t)[i].type);

			if (type > 0 && btf_is_ptr(btf__type_by_id(btf, type)))
				pointers |= 1U << i;
		}
		scan_set_proto(scan, func, pointers, !t->type);
	}
}

int fmodret_tag(Elf *elf, struct btf *btf, int verbose)
{
	size_t nr_funcs = 0, nr_scanned = 0, nr_undecodable = 0, nr_tags = 0;
	const struct btf *base = btf__base_btf(btf);
	__u32 id, nr_types = btf__type_cnt(btf);
	struct scan *scan = NULL;
	struct image img;
	char counts[200];
	int err;

	err = image_open(&img, elf);
	if (err)
		goto out;
	err = -EINVAL;
	scan = scan_open(&img);
	if (!scan)
		goto out;
	set_protos(scan, &img, btf);

	for (id = base ? btf__type_cnt(base) : 1, err = 0; id < nr_types && err >= 0; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		const struct image_func *func;
		const int64_t *values;
		const char *name;
		__u32 size;

		if (!btf_is_func(t))
			continue;
		nr_funcs++;
		size = int_return_size(btf, t);
		if (size != 4 && size != 8)
			continue;
		/* Init code is gone before a program can attach */
		name = btf__name_by_offset(btf, t->name_off);
		func = image_func(&img, name);
		if (!func || !strcmp(func->section, ".init.text"))
			continue;
		nr_scanned++;
		err = scan_func(scan, func, &values);
		if (err == -EINVAL) {
			nr_undecodable++;
			err = 0;
		}
		if (err > 0) {
			char tag[sizeof(TAG) + 6 * err];

			if (!format_tag(tag, values, err, size))
				continue;
			if (verbose > 1)
				fprintf(stderr, "fmodret: %s %s\n", name, tag + strlen(TAG));
			err = btf__add_decl_tag(btf, tag, id, -1);
			nr_tags++;
		}
	}
	snprintf(counts, sizeof(counts),
		 "%zu of %zu functions are tagged, %zu of the %zu which were scanned cannot be decoded",
		 nr_tags, nr_funcs, nr_undecodable, nr_scanned);
	/*
	 * A function which cannot be decoded costs a target, not the build. But
	 * if the decoder is lost in the code of vmlinux, don't leave that to be
	 * found out by a program which does not load.
	 */
	if (err >= 0 && !base && (!nr_tags || nr_undecodable > nr_scanned / 100)) {
		fprintf(stderr, "FAILED: --fmodret_scan: %s\n", counts);
		err = -EINVAL;
	} else if (!base || verbose) {
		printf("  FMODRET %s\n", counts);
	}
out:
	scan_close(scan);
	image_close(&img);
	return err < 0 ? err : 0;
}
