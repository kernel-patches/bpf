// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2019 Facebook */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_internal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bpf/btf.h>

#include "json_writer.h"
#include "main.h"

#define MAX_OBJ_NAME_LEN 64

static void sanitize_identifier(char *name)
{
	int i;

	for (i = 0; name[i]; i++)
		if (!isalnum(name[i]) && name[i] != '_')
			name[i] = '_';
}

static bool str_has_prefix(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool str_has_suffix(const char *str, const char *suffix)
{
	size_t i, n1 = strlen(str), n2 = strlen(suffix);

	if (n1 < n2)
		return false;

	for (i = 0; i < n2; i++) {
		if (str[n1 - i - 1] != suffix[n2 - i - 1])
			return false;
	}

	return true;
}

static void get_obj_name(char *name, const char *file)
{
	/* Using basename() GNU version which doesn't modify arg. */
	strncpy(name, basename(file), MAX_OBJ_NAME_LEN - 1);
	name[MAX_OBJ_NAME_LEN - 1] = '\0';
	if (str_has_suffix(name, ".o"))
		name[strlen(name) - 2] = '\0';
	sanitize_identifier(name);
}

static void get_header_guard(char *guard, const char *obj_name)
{
	int i;

	sprintf(guard, "__%s_SKEL_H__", obj_name);
	for (i = 0; guard[i]; i++)
		guard[i] = toupper(guard[i]);
}

static bool get_map_ident(const struct bpf_map *map, char *buf, size_t buf_sz)
{
	static const char *sfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	const char *name = bpf_map__name(map);
	int i, n;

	if (!bpf_map__is_internal(map)) {
		snprintf(buf, buf_sz, "%s", name);
		return true;
	}

	for  (i = 0, n = ARRAY_SIZE(sfxs); i < n; i++) {
		const char *sfx = sfxs[i], *p;

		p = strstr(name, sfx);
		if (p) {
			snprintf(buf, buf_sz, "%s", p + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static bool get_datasec_ident(const char *sec_name, char *buf, size_t buf_sz)
{
	static const char *pfxs[] = { ".data", ".rodata", ".bss", ".kconfig" };
	int i, n;

	for  (i = 0, n = ARRAY_SIZE(pfxs); i < n; i++) {
		const char *pfx = pfxs[i];

		if (str_has_prefix(sec_name, pfx)) {
			snprintf(buf, buf_sz, "%s", sec_name + 1);
			sanitize_identifier(buf);
			return true;
		}
	}

	return false;
}

static void codegen_btf_dump_printf(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

static int codegen_datasec_def(struct bpf_object *obj,
			       struct btf *btf,
			       struct btf_dump *d,
			       const struct btf_type *sec,
			       const char *obj_name)
{
	const char *sec_name = btf__name_by_offset(btf, sec->name_off);
	const struct btf_var_secinfo *sec_var = btf_var_secinfos(sec);
	int i, err, off = 0, pad_cnt = 0, vlen = btf_vlen(sec);
	char var_ident[256], sec_ident[256];
	bool strip_mods = false;

	if (!get_datasec_ident(sec_name, sec_ident, sizeof(sec_ident)))
		return 0;

	if (strcmp(sec_name, ".kconfig") != 0)
		strip_mods = true;

	printf("	struct %s__%s {\n", obj_name, sec_ident);
	for (i = 0; i < vlen; i++, sec_var++) {
		const struct btf_type *var = btf__type_by_id(btf, sec_var->type);
		const char *var_name = btf__name_by_offset(btf, var->name_off);
		DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts,
			.field_name = var_ident,
			.indent_level = 2,
			.strip_mods = strip_mods,
		);
		int need_off = sec_var->offset, align_off, align;
		__u32 var_type_id = var->type;

		/* static variables are not exposed through BPF skeleton */
		if (btf_var(var)->linkage == BTF_VAR_STATIC)
			continue;

		if (off > need_off) {
			p_err("Something is wrong for %s's variable #%d: need offset %d, already at %d.\n",
			      sec_name, i, need_off, off);
			return -EINVAL;
		}

		align = btf__align_of(btf, var->type);
		if (align <= 0) {
			p_err("Failed to determine alignment of variable '%s': %d",
			      var_name, align);
			return -EINVAL;
		}
		/* Assume 32-bit architectures when generating data section
		 * struct memory layout. Given bpftool can't know which target
		 * host architecture it's emitting skeleton for, we need to be
		 * conservative and assume 32-bit one to ensure enough padding
		 * bytes are generated for pointer and long types. This will
		 * still work correctly for 64-bit architectures, because in
		 * the worst case we'll generate unnecessary padding field,
		 * which on 64-bit architectures is not strictly necessary and
		 * would be handled by natural 8-byte alignment. But it still
		 * will be a correct memory layout, based on recorded offsets
		 * in BTF.
		 */
		if (align > 4)
			align = 4;

		align_off = (off + align - 1) / align * align;
		if (align_off != need_off) {
			printf("\t\tchar __pad%d[%d];\n",
			       pad_cnt, need_off - off);
			pad_cnt++;
		}

		/* sanitize variable name, e.g., for static vars inside
		 * a function, it's name is '<function name>.<variable name>',
		 * which we'll turn into a '<function name>_<variable name>'
		 */
		var_ident[0] = '\0';
		strncat(var_ident, var_name, sizeof(var_ident) - 1);
		sanitize_identifier(var_ident);

		printf("\t\t");
		err = btf_dump__emit_type_decl(d, var_type_id, &opts);
		if (err)
			return err;
		printf(";\n");

		off = sec_var->offset + sec_var->size;
	}
	printf("	} *%s;\n", sec_ident);
	return 0;
}

static int codegen_datasecs(struct bpf_object *obj, const char *obj_name)
{
	struct btf *btf = bpf_object__btf(obj);
	int n = btf__type_cnt(btf);
	struct btf_dump *d;
	struct bpf_map *map;
	const struct btf_type *sec;
	char sec_ident[256], map_ident[256];
	int i, err = 0;

	d = btf_dump__new(btf, codegen_btf_dump_printf, NULL, NULL);
	err = libbpf_get_error(d);
	if (err)
		return err;

	bpf_object__for_each_map(map, obj) {
		/* only generate definitions for memory-mapped internal maps */
		if (!bpf_map__is_internal(map))
			continue;
		if (!(bpf_map__def(map)->map_flags & BPF_F_MMAPABLE))
			continue;

		if (!get_map_ident(map, map_ident, sizeof(map_ident)))
			continue;

		sec = NULL;
		for (i = 1; i < n; i++) {
			const struct btf_type *t = btf__type_by_id(btf, i);
			const char *name;

			if (!btf_is_datasec(t))
				continue;

			name = btf__str_by_offset(btf, t->name_off);
			if (!get_datasec_ident(name, sec_ident, sizeof(sec_ident)))
				continue;

			if (strcmp(sec_ident, map_ident) == 0) {
				sec = t;
				break;
			}
		}

		/* In some cases (e.g., sections like .rodata.cst16 containing
		 * compiler allocated string constants only) there will be
		 * special internal maps with no corresponding DATASEC BTF
		 * type. In such case, generate empty structs for each such
		 * map. It will still be memory-mapped and its contents
		 * accessible from user-space through BPF skeleton.
		 */
		if (!sec) {
			printf("	struct %s__%s {\n", obj_name, map_ident);
			printf("	} *%s;\n", map_ident);
		} else {
			err = codegen_datasec_def(obj, btf, d, sec, obj_name);
			if (err)
				goto out;
		}
	}


out:
	btf_dump__free(d);
	return err;
}

static void codegen(const char *template, ...)
{
	const char *src, *end;
	int skip_tabs = 0, n;
	char *s, *dst;
	va_list args;
	char c;

	n = strlen(template);
	s = malloc(n + 1);
	if (!s)
		exit(-1);
	src = template;
	dst = s;

	/* find out "baseline" indentation to skip */
	while ((c = *src++)) {
		if (c == '\t') {
			skip_tabs++;
		} else if (c == '\n') {
			break;
		} else {
			p_err("unrecognized character at pos %td in template '%s': '%c'",
			      src - template - 1, template, c);
			free(s);
			exit(-1);
		}
	}

	while (*src) {
		/* skip baseline indentation tabs */
		for (n = skip_tabs; n > 0; n--, src++) {
			if (*src != '\t') {
				p_err("not enough tabs at pos %td in template '%s'",
				      src - template - 1, template);
				free(s);
				exit(-1);
			}
		}
		/* trim trailing whitespace */
		end = strchrnul(src, '\n');
		for (n = end - src; n > 0 && isspace(src[n - 1]); n--)
			;
		memcpy(dst, src, n);
		dst += n;
		if (*end)
			*dst++ = '\n';
		src = *end ? end + 1 : end;
	}
	*dst++ = '\0';

	/* print out using adjusted template */
	va_start(args, template);
	n = vprintf(s, args);
	va_end(args);

	free(s);
}

static void print_hex(const char *data, int data_sz)
{
	int i, len;

	for (i = 0, len = 0; i < data_sz; i++) {
		int w = data[i] ? 4 : 2;

		len += w;
		if (len > 78) {
			printf("\\\n");
			len = w;
		}
		if (!data[i])
			printf("\\0");
		else
			printf("\\x%02x", (unsigned char)data[i]);
	}
}

static size_t bpf_map_mmap_sz(const struct bpf_map *map)
{
	long page_sz = sysconf(_SC_PAGE_SIZE);
	size_t map_sz;

	map_sz = (size_t)roundup(bpf_map__value_size(map), 8) * bpf_map__max_entries(map);
	map_sz = roundup(map_sz, page_sz);
	return map_sz;
}

static void codegen_attach_detach(struct bpf_object *obj, const char *obj_name)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		const char *tp_name;

		codegen("\
			\n\
			\n\
			static inline int					    \n\
			%1$s__%2$s__attach(struct %1$s *skel)			    \n\
			{							    \n\
				int prog_fd = skel->progs.%2$s.prog_fd;		    \n\
			", obj_name, bpf_program__name(prog));

		switch (bpf_program__get_type(prog)) {
		case BPF_PROG_TYPE_RAW_TRACEPOINT:
			tp_name = strchr(bpf_program__section_name(prog), '/') + 1;
			printf("\tint fd = bpf_raw_tracepoint_open(\"%s\", prog_fd);\n", tp_name);
			break;
		case BPF_PROG_TYPE_TRACING:
			printf("\tint fd = bpf_raw_tracepoint_open(NULL, prog_fd);\n");
			break;
		default:
			printf("\tint fd = ((void)prog_fd, 0); /* auto-attach not supported */\n");
			break;
		}
		codegen("\
			\n\
										    \n\
				if (fd > 0)					    \n\
					skel->links.%1$s_fd = fd;		    \n\
				return fd;					    \n\
			}							    \n\
			", bpf_program__name(prog));
	}

	codegen("\
		\n\
									    \n\
		static inline int					    \n\
		%1$s__attach(struct %1$s *skel)				    \n\
		{							    \n\
			int ret = 0;					    \n\
									    \n\
		", obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				ret = ret < 0 ? ret : %1$s__%2$s__attach(skel);   \n\
			", obj_name, bpf_program__name(prog));
	}

	codegen("\
		\n\
			return ret < 0 ? ret : 0;			    \n\
		}							    \n\
									    \n\
		static inline void					    \n\
		%1$s__detach(struct %1$s *skel)				    \n\
		{							    \n\
		", obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				skel_closenz(skel->links.%1$s_fd);	    \n\
			", bpf_program__name(prog));
	}

	codegen("\
		\n\
		}							    \n\
		");
}

static void codegen_destroy(struct bpf_object *obj, const char *obj_name)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	char ident[256];

	codegen("\
		\n\
		static void						    \n\
		%1$s__destroy(struct %1$s *skel)			    \n\
		{							    \n\
			if (!skel)					    \n\
				return;					    \n\
			%1$s__detach(skel);				    \n\
		",
		obj_name);

	bpf_object__for_each_program(prog, obj) {
		codegen("\
			\n\
				skel_closenz(skel->progs.%1$s.prog_fd);	    \n\
			", bpf_program__name(prog));
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;
		if (bpf_map__is_internal(map) &&
		    (bpf_map__def(map)->map_flags & BPF_F_MMAPABLE))
			printf("\tmunmap(skel->%1$s, %2$zd);\n",
			       ident, bpf_map_mmap_sz(map));
		codegen("\
			\n\
				skel_closenz(skel->maps.%1$s.map_fd);	    \n\
			", ident);
	}
	codegen("\
		\n\
			free(skel);					    \n\
		}							    \n\
		",
		obj_name);
}

static int gen_trace(struct bpf_object *obj, const char *obj_name, const char *header_guard)
{
	DECLARE_LIBBPF_OPTS(gen_loader_opts, opts);
	struct bpf_map *map;
	char ident[256];
	int err = 0;

	err = bpf_object__gen_loader(obj, &opts);
	if (err)
		return err;

	err = bpf_object__load(obj);
	if (err) {
		p_err("failed to load object file");
		goto out;
	}
	/* If there was no error during load then gen_loader_opts
	 * are populated with the loader program.
	 */

	/* finish generating 'struct skel' */
	codegen("\
		\n\
		};							    \n\
		", obj_name);


	codegen_attach_detach(obj, obj_name);

	codegen_destroy(obj, obj_name);

	codegen("\
		\n\
		static inline struct %1$s *				    \n\
		%1$s__open(void)					    \n\
		{							    \n\
			struct %1$s *skel;				    \n\
									    \n\
			skel = calloc(sizeof(*skel), 1);		    \n\
			if (!skel)					    \n\
				goto cleanup;				    \n\
			skel->ctx.sz = (void *)&skel->links - (void *)skel; \n\
		",
		obj_name, opts.data_sz);
	bpf_object__for_each_map(map, obj) {
		const void *mmap_data = NULL;
		size_t mmap_size = 0;

		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;

		if (!bpf_map__is_internal(map) ||
		    !(bpf_map__def(map)->map_flags & BPF_F_MMAPABLE))
			continue;

		codegen("\
			\n\
				skel->%1$s =					 \n\
					mmap(NULL, %2$zd, PROT_READ | PROT_WRITE,\n\
					     MAP_SHARED | MAP_ANONYMOUS, -1, 0); \n\
				if (skel->%1$s == (void *) -1)			 \n\
					goto cleanup;				 \n\
				memcpy(skel->%1$s, (void *)\"\\			 \n\
			", ident, bpf_map_mmap_sz(map));
		mmap_data = bpf_map__initial_value(map, &mmap_size);
		print_hex(mmap_data, mmap_size);
		printf("\", %2$zd);\n"
		       "\tskel->maps.%1$s.initial_value = (__u64)(long)skel->%1$s;\n",
		       ident, mmap_size);
	}
	codegen("\
		\n\
			return skel;					    \n\
		cleanup:						    \n\
			%1$s__destroy(skel);				    \n\
			return NULL;					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__load(struct %1$s *skel)				    \n\
		{							    \n\
			struct bpf_load_and_run_opts opts = {};		    \n\
			int err;					    \n\
									    \n\
			opts.ctx = (struct bpf_loader_ctx *)skel;	    \n\
			opts.data_sz = %2$d;				    \n\
			opts.data = (void *)\"\\			    \n\
		",
		obj_name, opts.data_sz);
	print_hex(opts.data, opts.data_sz);
	codegen("\
		\n\
		\";							    \n\
		");

	codegen("\
		\n\
			opts.insns_sz = %d;				    \n\
			opts.insns = (void *)\"\\			    \n\
		",
		opts.insns_sz);
	print_hex(opts.insns, opts.insns_sz);
	codegen("\
		\n\
		\";							    \n\
			err = bpf_load_and_run(&opts);			    \n\
			if (err < 0)					    \n\
				return err;				    \n\
		", obj_name);
	bpf_object__for_each_map(map, obj) {
		const char *mmap_flags;

		if (!get_map_ident(map, ident, sizeof(ident)))
			continue;

		if (!bpf_map__is_internal(map) ||
		    !(bpf_map__def(map)->map_flags & BPF_F_MMAPABLE))
			continue;

		if (bpf_map__def(map)->map_flags & BPF_F_RDONLY_PROG)
			mmap_flags = "PROT_READ";
		else
			mmap_flags = "PROT_READ | PROT_WRITE";

		printf("\tskel->%1$s =\n"
		       "\t\tmmap(skel->%1$s, %2$zd, %3$s, MAP_SHARED | MAP_FIXED,\n"
		       "\t\t\tskel->maps.%1$s.map_fd, 0);\n",
		       ident, bpf_map_mmap_sz(map), mmap_flags);
	}
	codegen("\
		\n\
			return 0;					    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_and_load(void)				    \n\
		{							    \n\
			struct %1$s *skel;				    \n\
									    \n\
			skel = %1$s__open();				    \n\
			if (!skel)					    \n\
				return NULL;				    \n\
			if (%1$s__load(skel)) {				    \n\
				%1$s__destroy(skel);			    \n\
				return NULL;				    \n\
			}						    \n\
			return skel;					    \n\
		}							    \n\
		", obj_name);

	codegen("\
		\n\
									    \n\
		#endif /* %s */						    \n\
		",
		header_guard);
	err = 0;
out:
	return err;
}

static int do_skeleton(int argc, char **argv)
{
	char header_guard[MAX_OBJ_NAME_LEN + sizeof("__SKEL_H__")];
	size_t i, map_cnt = 0, prog_cnt = 0, file_sz, mmap_sz;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	char obj_name[MAX_OBJ_NAME_LEN] = "", *obj_data;
	struct bpf_object *obj = NULL;
	const char *file;
	char ident[256];
	struct bpf_program *prog;
	int fd, err = -1;
	struct bpf_map *map;
	struct btf *btf;
	struct stat st;

	if (!REQ_ARGS(1)) {
		usage();
		return -1;
	}
	file = GET_ARG();

	while (argc) {
		if (!REQ_ARGS(2))
			return -1;

		if (is_prefix(*argv, "name")) {
			NEXT_ARG();

			if (obj_name[0] != '\0') {
				p_err("object name already specified");
				return -1;
			}

			strncpy(obj_name, *argv, MAX_OBJ_NAME_LEN - 1);
			obj_name[MAX_OBJ_NAME_LEN - 1] = '\0';
		} else {
			p_err("unknown arg %s", *argv);
			return -1;
		}

		NEXT_ARG();
	}

	if (argc) {
		p_err("extra unknown arguments");
		return -1;
	}

	if (stat(file, &st)) {
		p_err("failed to stat() %s: %s", file, strerror(errno));
		return -1;
	}
	file_sz = st.st_size;
	mmap_sz = roundup(file_sz, sysconf(_SC_PAGE_SIZE));
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		p_err("failed to open() %s: %s", file, strerror(errno));
		return -1;
	}
	obj_data = mmap(NULL, mmap_sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (obj_data == MAP_FAILED) {
		obj_data = NULL;
		p_err("failed to mmap() %s: %s", file, strerror(errno));
		goto out;
	}
	if (obj_name[0] == '\0')
		get_obj_name(obj_name, file);
	opts.object_name = obj_name;
	if (verifier_logs)
		/* log_level1 + log_level2 + stats, but not stable UAPI */
		opts.kernel_log_level = 1 + 2 + 4;
	obj = bpf_object__open_mem(obj_data, file_sz, &opts);
	err = libbpf_get_error(obj);
	if (err) {
		char err_buf[256];

		libbpf_strerror(err, err_buf, sizeof(err_buf));
		p_err("failed to open BPF object file: %s", err_buf);
		obj = NULL;
		goto out;
	}

	bpf_object__for_each_map(map, obj) {
		if (!get_map_ident(map, ident, sizeof(ident))) {
			p_err("ignoring unrecognized internal map '%s'...",
			      bpf_map__name(map));
			continue;
		}
		map_cnt++;
	}
	bpf_object__for_each_program(prog, obj) {
		prog_cnt++;
	}

	get_header_guard(header_guard, obj_name);
	if (use_loader) {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
		/* THIS FILE IS AUTOGENERATED! */			    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <stdlib.h>					    \n\
		#include <bpf/bpf.h>					    \n\
		#include <bpf/skel_internal.h>				    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_loader_ctx ctx;			    \n\
		",
		obj_name, header_guard
		);
	} else {
		codegen("\
		\n\
		/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */   \n\
									    \n\
		/* THIS FILE IS AUTOGENERATED! */			    \n\
		#ifndef %2$s						    \n\
		#define %2$s						    \n\
									    \n\
		#include <errno.h>					    \n\
		#include <stdlib.h>					    \n\
		#include <bpf/libbpf.h>					    \n\
									    \n\
		struct %1$s {						    \n\
			struct bpf_object_skeleton *skeleton;		    \n\
			struct bpf_object *obj;				    \n\
		",
		obj_name, header_guard
		);
	}

	if (map_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_map(map, obj) {
			if (!get_map_ident(map, ident, sizeof(ident)))
				continue;
			if (use_loader)
				printf("\t\tstruct bpf_map_desc %s;\n", ident);
			else
				printf("\t\tstruct bpf_map *%s;\n", ident);
		}
		printf("\t} maps;\n");
	}

	if (prog_cnt) {
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tstruct bpf_prog_desc %s;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_program *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} progs;\n");
		printf("\tstruct {\n");
		bpf_object__for_each_program(prog, obj) {
			if (use_loader)
				printf("\t\tint %s_fd;\n",
				       bpf_program__name(prog));
			else
				printf("\t\tstruct bpf_link *%s;\n",
				       bpf_program__name(prog));
		}
		printf("\t} links;\n");
	}

	btf = bpf_object__btf(obj);
	if (btf) {
		err = codegen_datasecs(obj, obj_name);
		if (err)
			goto out;
	}
	if (use_loader) {
		err = gen_trace(obj, obj_name, header_guard);
		goto out;
	}

	codegen("\
		\n\
		};							    \n\
									    \n\
		static void						    \n\
		%1$s__destroy(struct %1$s *obj)				    \n\
		{							    \n\
			if (!obj)					    \n\
				return;					    \n\
			if (obj->skeleton)				    \n\
				bpf_object__destroy_skeleton(obj->skeleton);\n\
			free(obj);					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__create_skeleton(struct %1$s *obj);		    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_opts(const struct bpf_object_open_opts *opts)    \n\
		{							    \n\
			struct %1$s *obj;				    \n\
			int err;					    \n\
									    \n\
			obj = (struct %1$s *)calloc(1, sizeof(*obj));	    \n\
			if (!obj) {					    \n\
				errno = ENOMEM;				    \n\
				return NULL;				    \n\
			}						    \n\
									    \n\
			err = %1$s__create_skeleton(obj);		    \n\
			if (err)					    \n\
				goto err_out;				    \n\
									    \n\
			err = bpf_object__open_skeleton(obj->skeleton, opts);\n\
			if (err)					    \n\
				goto err_out;				    \n\
									    \n\
			return obj;					    \n\
		err_out:						    \n\
			%1$s__destroy(obj);				    \n\
			errno = -err;					    \n\
			return NULL;					    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open(void)					    \n\
		{							    \n\
			return %1$s__open_opts(NULL);			    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__load(struct %1$s *obj)				    \n\
		{							    \n\
			return bpf_object__load_skeleton(obj->skeleton);    \n\
		}							    \n\
									    \n\
		static inline struct %1$s *				    \n\
		%1$s__open_and_load(void)				    \n\
		{							    \n\
			struct %1$s *obj;				    \n\
			int err;					    \n\
									    \n\
			obj = %1$s__open();				    \n\
			if (!obj)					    \n\
				return NULL;				    \n\
			err = %1$s__load(obj);				    \n\
			if (err) {					    \n\
				%1$s__destroy(obj);			    \n\
				errno = -err;				    \n\
				return NULL;				    \n\
			}						    \n\
			return obj;					    \n\
		}							    \n\
									    \n\
		static inline int					    \n\
		%1$s__attach(struct %1$s *obj)				    \n\
		{							    \n\
			return bpf_object__attach_skeleton(obj->skeleton);  \n\
		}							    \n\
									    \n\
		static inline void					    \n\
		%1$s__detach(struct %1$s *obj)				    \n\
		{							    \n\
			return bpf_object__detach_skeleton(obj->skeleton);  \n\
		}							    \n\
		",
		obj_name
	);

	codegen("\
		\n\
									    \n\
		static inline const void *%1$s__elf_bytes(size_t *sz);	    \n\
									    \n\
		static inline int					    \n\
		%1$s__create_skeleton(struct %1$s *obj)			    \n\
		{							    \n\
			struct bpf_object_skeleton *s;			    \n\
									    \n\
			s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));\n\
			if (!s)						    \n\
				goto err;				    \n\
			obj->skeleton = s;				    \n\
									    \n\
			s->sz = sizeof(*s);				    \n\
			s->name = \"%1$s\";				    \n\
			s->obj = &obj->obj;				    \n\
		",
		obj_name
	);
	if (map_cnt) {
		codegen("\
			\n\
									    \n\
				/* maps */				    \n\
				s->map_cnt = %zu;			    \n\
				s->map_skel_sz = sizeof(*s->maps);	    \n\
				s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);\n\
				if (!s->maps)				    \n\
					goto err;			    \n\
			",
			map_cnt
		);
		i = 0;
		bpf_object__for_each_map(map, obj) {
			if (!get_map_ident(map, ident, sizeof(ident)))
				continue;

			codegen("\
				\n\
									    \n\
					s->maps[%zu].name = \"%s\";	    \n\
					s->maps[%zu].map = &obj->maps.%s;   \n\
				",
				i, bpf_map__name(map), i, ident);
			/* memory-mapped internal maps */
			if (bpf_map__is_internal(map) &&
			    (bpf_map__def(map)->map_flags & BPF_F_MMAPABLE)) {
				printf("\ts->maps[%zu].mmaped = (void **)&obj->%s;\n",
				       i, ident);
			}
			i++;
		}
	}
	if (prog_cnt) {
		codegen("\
			\n\
									    \n\
				/* programs */				    \n\
				s->prog_cnt = %zu;			    \n\
				s->prog_skel_sz = sizeof(*s->progs);	    \n\
				s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);\n\
				if (!s->progs)				    \n\
					goto err;			    \n\
			",
			prog_cnt
		);
		i = 0;
		bpf_object__for_each_program(prog, obj) {
			codegen("\
				\n\
									    \n\
					s->progs[%1$zu].name = \"%2$s\";    \n\
					s->progs[%1$zu].prog = &obj->progs.%2$s;\n\
					s->progs[%1$zu].link = &obj->links.%2$s;\n\
				",
				i, bpf_program__name(prog));
			i++;
		}
	}
	codegen("\
		\n\
									    \n\
			s->data = (void *)%2$s__elf_bytes(&s->data_sz);	    \n\
									    \n\
			return 0;					    \n\
		err:							    \n\
			bpf_object__destroy_skeleton(s);		    \n\
			return -ENOMEM;					    \n\
		}							    \n\
									    \n\
		static inline const void *%2$s__elf_bytes(size_t *sz)	    \n\
		{							    \n\
			*sz = %1$d;					    \n\
			return (const void *)\"\\			    \n\
		"
		, file_sz, obj_name);

	/* embed contents of BPF object file */
	print_hex(obj_data, file_sz);

	codegen("\
		\n\
		\";							    \n\
		}							    \n\
									    \n\
		#endif /* %s */						    \n\
		",
		header_guard);
	err = 0;
out:
	bpf_object__close(obj);
	if (obj_data)
		munmap(obj_data, mmap_sz);
	close(fd);
	return err;
}

static int do_object(int argc, char **argv)
{
	struct bpf_linker *linker;
	const char *output_file, *file;
	int err = 0;

	if (!REQ_ARGS(2)) {
		usage();
		return -1;
	}

	output_file = GET_ARG();

	linker = bpf_linker__new(output_file, NULL);
	if (!linker) {
		p_err("failed to create BPF linker instance");
		return -1;
	}

	while (argc) {
		file = GET_ARG();

		err = bpf_linker__add_file(linker, file, NULL);
		if (err) {
			p_err("failed to link '%s': %s (%d)", file, strerror(err), err);
			goto out;
		}
	}

	err = bpf_linker__finalize(linker);
	if (err) {
		p_err("failed to finalize ELF file: %s (%d)", strerror(err), err);
		goto out;
	}

	err = 0;
out:
	bpf_linker__free(linker);
	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s object OUTPUT_FILE INPUT_FILE [INPUT_FILE...]\n"
		"       %1$s %2$s skeleton FILE [name OBJECT_NAME]\n"
		"       %1$s %2$s btf INPUT OUTPUT OBJECT(S)\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-L|--use-loader} }\n"
		"",
		bin_name, "gen");

	return 0;
}

static int btf_save_raw(const struct btf *btf, const char *path)
{
	const void *data;
	FILE *f = NULL;
	__u32 data_sz;
	int err = 0;

	data = btf__raw_data(btf, &data_sz);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}

	f = fopen(path, "wb");
	if (!f) {
		err = -errno;
		goto out;
	}

	if (fwrite(data, 1, data_sz, f) != data_sz) {
		err = -errno;
		goto out;
	}

out:
	if (f)
		fclose(f);
	return libbpf_err(err);
}

struct btf_reloc_member {
	struct btf_member *member;
	int idx;
};

struct btf_reloc_type {
	struct btf_type *type;
	unsigned int id;
	bool added_by_all;

	struct hashmap *members;
};

struct btf_reloc_info {
	struct hashmap *types;
	struct hashmap *ids_map;

	struct btf *src_btf;
};

static size_t bpf_reloc_info_hash_fn(const void *key, void *ctx)
{
	return (size_t)key;
}

static bool bpf_reloc_info_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

static void *uint_as_hash_key(int x)
{
	return (void *)(uintptr_t)x;
}

static void bpf_reloc_type_free(struct btf_reloc_type *type)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (IS_ERR_OR_NULL(type))
		return;

	if (!IS_ERR_OR_NULL(type->members)) {
		hashmap__for_each_entry(type->members, entry, bkt) {
			free(entry->value);
		}
		hashmap__free(type->members);
	}

	free(type);
}

static void btfgen_reloc_info_free(struct btf_reloc_info *info)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (!info)
		return;

	hashmap__free(info->ids_map);

	if (!IS_ERR_OR_NULL(info->types)) {
		hashmap__for_each_entry(info->types, entry, bkt) {
			bpf_reloc_type_free(entry->value);
		}
		hashmap__free(info->types);
	}

	btf__free(info->src_btf);

	free(info);
}

static struct btf_reloc_info *
btfgen_reloc_info_new(const char *targ_btf_path)
{
	struct btf_reloc_info *info;
	struct btf *src_btf;
	struct hashmap *ids_map;
	struct hashmap *types;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ERR_PTR(-ENOMEM);

	src_btf = btf__parse(targ_btf_path, NULL);
	if (libbpf_get_error(src_btf)) {
		btfgen_reloc_info_free(info);
		return (void *) src_btf;
	}

	info->src_btf = src_btf;

	ids_map = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(ids_map)) {
		btfgen_reloc_info_free(info);
		return (void *) ids_map;
	}

	info->ids_map = ids_map;

	types = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(types)) {
		btfgen_reloc_info_free(info);
		return (void *) types;
	}

	info->types = types;

	return info;
}

/* Return id for type in new btf instance */
static unsigned int btf_reloc_id_get(struct btf_reloc_info *info, unsigned int old)
{
	uintptr_t new = 0;

	/* deal with BTF_KIND_VOID */
	if (old == 0)
		return 0;

	if (!hashmap__find(info->ids_map, uint_as_hash_key(old), (void **)&new)) {
		/* return id for void as it's possible that the ID we're looking for is
		 * the type of a pointer that we're not adding.
		 */
		return 0;
	}

	return (unsigned int)(uintptr_t)new;
}

/* Add new id map to the list of mappings */
static int btf_reloc_id_add(struct btf_reloc_info *info, unsigned int old, unsigned int new)
{
	return hashmap__add(info->ids_map, uint_as_hash_key(old), uint_as_hash_key(new));
}

/*
 * Put type in the list. If the type already exists it's returned, otherwise a
 * new one is created and added to the list. This is called recursively adding
 * all the types that are needed for the current one.
 */
static struct btf_reloc_type *btf_reloc_put_type(struct btf *btf,
						 struct btf_reloc_info *info,
						 struct btf_type *btf_type,
						 unsigned int id)
{
	struct btf_reloc_type *reloc_type, *tmp;
	struct btf_array *array;
	unsigned int child_id;
	int err;

	/* check if we already have this type */
	if (hashmap__find(info->types, uint_as_hash_key(id), (void **) &reloc_type))
		return reloc_type;


	/* do nothing. void is implicit in BTF */
	if (id == 0)
		return NULL;

	reloc_type = calloc(1, sizeof(*reloc_type));
	if (!reloc_type)
		return ERR_PTR(-ENOMEM);

	reloc_type->type = btf_type;
	reloc_type->id = id;

	/* append this type to the relocation type's list before anything else */
	err = hashmap__add(info->types, uint_as_hash_key(reloc_type->id), reloc_type);
	if (err)
		return ERR_PTR(err);

	/* complex types might need further processing */
	switch (btf_kind(reloc_type->type)) {
	/* already processed */
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	/* processed by callee */
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	/* doesn't need resolution. If the data of the pointer is used
	 * then it'll added by the caller in another relocation.
	 */
	case BTF_KIND_PTR:
		break;
	/* needs resolution */
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		child_id = btf_type->type;
		btf_type = (struct btf_type *) btf__type_by_id(btf, child_id);
		if (!btf_type)
			return ERR_PTR(-EINVAL);

		tmp = btf_reloc_put_type(btf, info, btf_type, child_id);
		if (IS_ERR(tmp))
			return tmp;
		break;
	/* needs resolution */
	case BTF_KIND_ARRAY:
		array = btf_array(reloc_type->type);

		/* add type for array type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
		tmp = btf_reloc_put_type(btf, info, btf_type, array->type);
		if (IS_ERR(tmp))
			return tmp;

		/* add type for array's index type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->index_type);
		tmp = btf_reloc_put_type(btf, info, btf_type, array->index_type);
		if (IS_ERR(tmp))
			return tmp;

		break;
	/* tells if some other type needs to be handled */
	default:
		p_err("unsupported relocation: %d", reloc_type->id);
		return ERR_PTR(-EINVAL);
	}

	return reloc_type;
}

/* Return pointer to btf_reloc_type by id */
static struct btf_reloc_type *btf_reloc_get_type(struct btf_reloc_info *info, int id)
{
	struct btf_reloc_type *type = NULL;

	if (!hashmap__find(info->types, uint_as_hash_key(id), (void **)&type))
		return ERR_PTR(-ENOENT);

	return type;
}

static int bpf_reloc_type_add_member(struct btf_reloc_info *info,
				     struct btf_reloc_type *reloc_type,
				     struct btf_member *btf_member, int idx)
{
	struct btf_reloc_member *reloc_member;
	int err;

	/* create new members hashmap for this relocation type if needed */
	if (reloc_type->members == NULL) {
		struct hashmap *tmp = hashmap__new(bpf_reloc_info_hash_fn,
						   bpf_reloc_info_equal_fn,
						   NULL);
		if (IS_ERR(tmp))
			return PTR_ERR(tmp);

		reloc_type->members = tmp;
	}
	/* add given btf_member as a member of the parent relocation_type's type */
	reloc_member = calloc(1, sizeof(*reloc_member));
	if (!reloc_member)
		return -ENOMEM;
	reloc_member->member = btf_member;
	reloc_member->idx = idx;
	/* add given btf_member as member to given relocation type */
	err = hashmap__add(reloc_type->members, uint_as_hash_key(reloc_member->idx), reloc_member);
	if (err) {
		free(reloc_member);
		if (err != -EEXIST)
			return err;
	}

	return 0;
}

/*
 * Same as btf_reloc_put_type, but adding all fields, from given complex type, recursively
 */
static int btf_reloc_put_type_all(struct btf *btf,
				  struct btf_reloc_info *info,
				  struct btf_type *btf_type,
				  unsigned int id)
{
	struct btf_reloc_type *reloc_type;
	struct btf_array *array;
	unsigned int child_id;
	struct btf_member *m;
	int err, i, n;

	if (id == 0)
		return 0;

	if (!hashmap__find(info->types, uint_as_hash_key(id), (void **) &reloc_type)) {
		reloc_type = calloc(1, sizeof(*reloc_type));
		if (!reloc_type)
			return -ENOMEM;

		reloc_type->type = btf_type;
		reloc_type->id = id;
		/* avoid infinite recursion and yet be able to add all
		 * fields/members for types also managed by this function twin
		 * brother btf_reloc_put_type()
		 */
		reloc_type->added_by_all = true;

		err = hashmap__add(info->types, uint_as_hash_key(reloc_type->id), reloc_type);
		if (err)
			return err;
	} else {
		if (reloc_type->added_by_all)
			return 0;

		reloc_type->added_by_all = true;
	}

	switch (btf_kind(reloc_type->type)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
		/* not a complex type, already solved */
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		n = btf_vlen(btf_type);
		m = btf_members(btf_type);
		for (i = 0; i < n; i++, m++) {
			btf_type = (struct btf_type *) btf__type_by_id(btf, m->type);
			if (!btf_type)
				return -EINVAL;

			/* add all member types */
			err = btf_reloc_put_type_all(btf, info, btf_type, m->type);
			if (err)
				return err;

			/* add all members */
			err = bpf_reloc_type_add_member(info, reloc_type, m, i);
			if (err)
				return err;
		}
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		/* modifier types */
		child_id = btf_type->type;
		btf_type = (struct btf_type *) btf__type_by_id(btf, child_id);
		if (!btf_type)
			return -EINVAL;

		err = btf_reloc_put_type_all(btf, info, btf_type, child_id);
		if (err)
			return err;
		break;
	case BTF_KIND_ARRAY:
		array = btf_array(btf_type);

		/* add array member type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
		if (!btf_type)
			return -EINVAL;
		err = btf_reloc_put_type_all(btf, info, btf_type, array->type);
		if (err)
			return err;

		/* add array index type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->index_type);
		if (!btf_type)
			return -EINVAL;
		err = btf_reloc_put_type_all(btf, info, btf_type, array->type);
		if (err)
			return err;
		break;
	default:
		p_err("unsupported kind (all): %s (%d)",
		      btf_kind_str(reloc_type->type), reloc_type->id);
		return -EINVAL;
	}

	return 0;
}

static int btf_reloc_info_gen_field(struct btf_reloc_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = (struct btf *) info->src_btf;
	struct btf_reloc_type *reloc_type;
	struct btf_member *btf_member;
	struct btf_type *btf_type;
	struct btf_array *array;
	unsigned int id;
	int idx, err;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	/* create reloc type for root type */
	reloc_type = btf_reloc_put_type(btf, info, btf_type, targ_spec->root_type_id);
	if (IS_ERR(reloc_type))
		return PTR_ERR(reloc_type);

	/* add types for complex types (arrays, unions, structures) */
	for (int i = 1; i < targ_spec->raw_len; i++) {
		/* skip typedefs and mods */
		while (btf_is_mod(btf_type) || btf_is_typedef(btf_type)) {
			id = btf_type->type;
			reloc_type = btf_reloc_get_type(info, id);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			btf_type = (struct btf_type *) btf__type_by_id(btf, id);
		}

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			idx = targ_spec->raw_spec[i];
			btf_member = btf_members(btf_type) + idx;
			btf_type =  (struct btf_type *) btf__type_by_id(btf, btf_member->type);

			/* add member to relocation type */
			err = bpf_reloc_type_add_member(info, reloc_type, btf_member, idx);
			if (err)
				return err;
			/* add relocation type */
			reloc_type = btf_reloc_put_type(btf, info, btf_type, btf_member->type);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			reloc_type = btf_reloc_get_type(info, array->type);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
			break;
		default:
			p_err("spec type wasn't handled");
			return -1;
		}
	}

	return 0;
}

static int btf_reloc_info_gen_type(struct btf_reloc_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = (struct btf *) info->src_btf;
	struct btf_type *btf_type;
	int err = 0;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	return btf_reloc_put_type_all(btf, info, btf_type, targ_spec->root_type_id);
}

static int btf_reloc_info_gen_enumval(struct btf_reloc_info *info, struct bpf_core_spec *targ_spec)
{
	p_err("untreated enumval based relocation");
	return -EOPNOTSUPP;
}

static int btf_reloc_info_gen(struct btf_reloc_info *info, struct bpf_core_spec *res)
{
	if (core_relo_is_type_based(res->relo_kind))
		return btf_reloc_info_gen_type(info, res);

	if (core_relo_is_enumval_based(res->relo_kind))
		return btf_reloc_info_gen_enumval(info, res);

	if (core_relo_is_field_based(res->relo_kind))
		return btf_reloc_info_gen_field(info, res);

	return -EINVAL;
}

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

static int btfgen_obj_reloc_info_gen(struct btf_reloc_info *reloc_info, struct bpf_object *obj)
{
	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *rec;
	const struct btf_ext_info *seg;
	struct hashmap *cand_cache;
	int err, insn_idx, sec_idx;
	struct bpf_program *prog;
	struct btf_ext *btf_ext;
	const char *sec_name;
	size_t nr_programs;
	struct btf *btf;
	unsigned int i;

	btf = bpf_object__btf(obj);
	btf_ext = bpf_object__btf_ext(obj);

	if (btf_ext->core_relo_info.len == 0)
		return 0;

	cand_cache = bpf_core_create_cand_cache();
	if (IS_ERR(cand_cache))
		return PTR_ERR(cand_cache);

	bpf_object_set_vmlinux_override(obj, reloc_info->src_btf);

	seg = &btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec) {
		bool prog_found;

		sec_name = btf__name_by_offset(btf, sec->sec_name_off);
		if (str_is_empty(sec_name)) {
			err = -EINVAL;
			goto out;
		}

		prog_found = false;
		nr_programs = bpf_object__get_nr_programs(obj);
		for (i = 0; i < nr_programs; i++)	{
			prog = bpf_object__get_program(obj, i);
			if (strcmp(bpf_program__section_name(prog), sec_name) == 0) {
				prog_found = true;
				break;
			}
		}

		if (!prog_found) {
			pr_warn("sec '%s': failed to find a BPF program\n", sec_name);
			err = -EINVAL;
			goto out;
		}

		sec_idx = bpf_program__sec_idx(prog);

		for_each_btf_ext_rec(seg, sec, i, rec) {
			struct bpf_core_relo_res targ_res;
			struct bpf_core_spec targ_spec;

			insn_idx = rec->insn_off / BPF_INSN_SZ;

			prog = find_prog_by_sec_insn(obj, sec_idx, insn_idx);
			if (!prog) {
				pr_warn("sec '%s': failed to find program at insn #%d for CO-RE offset relocation #%d\n",
					sec_name, insn_idx, i);
				err = -EINVAL;
				goto out;
			}

			err = bpf_core_calc_relo_res(prog, rec, i, btf, cand_cache, &targ_res,
						     &targ_spec);
			if (err)
				goto out;

			err = btf_reloc_info_gen(reloc_info, &targ_spec);
			if (err)
				goto out;
		}
	}

out:
	bpf_core_free_cand_cache(cand_cache);

	return err;
}

static struct btf *btfgen_reloc_info_get_btf(struct btf_reloc_info *info)
{
	struct hashmap_entry *entry;
	struct btf *btf_new;
	size_t bkt;
	int err;

	btf_new = btf__new_empty();
	if (IS_ERR(btf_new)) {
		p_err("failed to allocate btf structure");
		return btf_new;
	}

	/* first pass: add all types and add their new ids to the ids map */
	hashmap__for_each_entry(info->types, entry, bkt) {
		struct btf_reloc_type *reloc_type = entry->value;
		struct btf_type *btf_type = reloc_type->type;
		int new_id;

		/* add members for struct and union */
		if (btf_is_struct(btf_type) || btf_is_union(btf_type)) {
			struct hashmap_entry *member_entry;
			struct btf_type *btf_type_cpy;
			int nmembers, index;
			size_t new_size;

			nmembers = reloc_type->members ? hashmap__size(reloc_type->members) : 0;
			new_size = sizeof(struct btf_type) + nmembers * sizeof(struct btf_member);

			btf_type_cpy = malloc(new_size);
			if (!btf_type_cpy) {
				err = -ENOMEM;
				goto out;
			}

			/* copy header */
			memcpy(btf_type_cpy, btf_type, sizeof(*btf_type_cpy));

			/* copy only members that are needed */
			index = 0;
			if (nmembers > 0) {
				size_t bkt2;

				hashmap__for_each_entry(reloc_type->members, member_entry, bkt2) {
					struct btf_reloc_member *reloc_member;
					struct btf_member *btf_member;

					reloc_member = member_entry->value;
					btf_member = btf_members(btf_type) + reloc_member->idx;

					memcpy(btf_members(btf_type_cpy) + index, btf_member,
					       sizeof(struct btf_member));

					index++;
				}
			}

			/* set new vlen */
			btf_type_cpy->info = btf_type_info(btf_kind(btf_type_cpy), nmembers,
							   btf_kflag(btf_type_cpy));

			err = btf__add_type(btf_new, info->src_btf, btf_type_cpy);
			free(btf_type_cpy);
		} else {
			err = btf__add_type(btf_new, info->src_btf, btf_type);
		}

		if (err < 0)
			goto out;

		new_id = err;

		/* add ID mapping */
		err = btf_reloc_id_add(info, reloc_type->id, new_id);
		if (err)
			goto out;
	}

	/* second pass: fix up type ids */
	for (unsigned int i = 0; i < btf__type_cnt(btf_new); i++) {
		struct btf_member *btf_member;
		struct btf_type *btf_type;
		struct btf_param *params;
		struct btf_array *array;

		btf_type = (struct btf_type *) btf__type_by_id(btf_new, i);

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			for (unsigned short j = 0; j < btf_vlen(btf_type); j++) {
				btf_member = btf_members(btf_type) + j;
				btf_member->type = btf_reloc_id_get(info, btf_member->type);
			}
			break;
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
		case BTF_KIND_VAR:
			btf_type->type = btf_reloc_id_get(info, btf_type->type);
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			array->index_type = btf_reloc_id_get(info, array->index_type);
			array->type = btf_reloc_id_get(info, array->type);
			break;
		case BTF_KIND_FUNC_PROTO:
			btf_type->type = btf_reloc_id_get(info, btf_type->type);
			params = btf_params(btf_type);
			for (unsigned short j = 0; j < btf_vlen(btf_type); j++)
				params[j].type = btf_reloc_id_get(info, params[j].type);
			break;
		default:
			break;
		}
	}

	return btf_new;

out:
	btf__free(btf_new);
	return ERR_PTR(err);
}

static int is_file(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return -1;

	switch (st.st_mode & S_IFMT) {
	case S_IFDIR:
		return 0;
	case S_IFREG:
		return 1;
	default:
		return -1;
	}

	return -1;
}

static int generate_btf(const char *src_btf, const char *dst_btf, const char *objspaths[])
{
	struct btf_reloc_info *reloc_info;
	struct btf *btf_new = NULL;
	struct bpf_object *obj;
	int err;

	struct bpf_object_open_opts ops = {
		.sz = sizeof(ops),
		.btf_custom_path = src_btf,
	};

	reloc_info = btfgen_reloc_info_new(src_btf);
	err = libbpf_get_error(reloc_info);
	if (err) {
		p_err("failed to allocate info structure");
		goto out;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("OBJ : %s\n", objspaths[i]);
		obj = bpf_object__open_file(objspaths[i], &ops);
		err = libbpf_get_error(obj);
		if (err) {
			p_err("error opening object: %s", strerror(errno));
			goto out;
		}

		err = btfgen_obj_reloc_info_gen(reloc_info, obj);
		if (err)
			goto out;

		bpf_object__close(obj);
	}

	btf_new = btfgen_reloc_info_get_btf(reloc_info);
	err = libbpf_get_error(btf_new);
	if (err) {
		p_err("error generating btf: %s", strerror(errno));
		goto out;
	}

	printf("DBTF: %s\n", dst_btf);
	err = btf_save_raw(btf_new, dst_btf);
	if (err) {
		p_err("error saving btf file: %s", strerror(errno));
		goto out;
	}

out:
	if (!libbpf_get_error(btf_new))
		btf__free(btf_new);
	btfgen_reloc_info_free(reloc_info);

	return err;
}

static int do_gen_btf(int argc, char **argv)
{
	char src_btf_path[PATH_MAX], dst_btf_path[PATH_MAX];
	bool input_is_file, output_is_file = false;
	const char *input, *output;
	const char **objs = NULL;
	struct dirent *dir;
	DIR *d = NULL;
	int i, err;

	if (!REQ_ARGS(3)) {
		usage();
		return -1;
	}

	input = GET_ARG();
	err = is_file(input);
	if (err < 0) {
		p_err("failed to stat %s: %s", input, strerror(errno));
		return err;
	}
	input_is_file = err;

	output = GET_ARG();
	err = is_file(output);
	if (err != 0)
		output_is_file = true;

	objs = (const char **) malloc((argc + 1) * sizeof(*objs));
	if (!objs)
		return -ENOMEM;

	i = 0;
	while (argc > 0)
		objs[i++] = GET_ARG();

	objs[i] = NULL;

	// single BTF file
	if (input_is_file) {
		char *d_input;

		printf("SBTF: %s\n", input);

		if (output_is_file) {
			err = generate_btf(input, output, objs);
			goto out;
		}
		d_input = strdup(input);
		snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", output,
			 basename(d_input));
		free(d_input);
		err = generate_btf(input, dst_btf_path, objs);
		goto out;
	}

	if (output_is_file) {
		p_err("can't have just one file as output");
		err = -EINVAL;
		goto out;
	}

	// directory with BTF files
	d = opendir(input);
	if (!d) {
		p_err("error opening input dir: %s", strerror(errno));
		err = -errno;
		goto out;
	}

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_REG)
			continue;

		if (strncmp(dir->d_name + strlen(dir->d_name) - 4, ".btf", 4))
			continue;

		snprintf(src_btf_path, sizeof(src_btf_path), "%s/%s", input, dir->d_name);
		snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", output, dir->d_name);

		printf("SBTF: %s\n", src_btf_path);

		err = generate_btf(src_btf_path, dst_btf_path, objs);
		if (err)
			goto out;
	}

out:
	if (!err)
		printf("STAT: done!\n");
	free(objs);
	closedir(d);
	return err;
}

static const struct cmd cmds[] = {
	{ "object",	do_object },
	{ "skeleton",	do_skeleton },
	{ "btf",	do_gen_btf},
	{ "help",	do_help },
	{ 0 }
};

int do_gen(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
