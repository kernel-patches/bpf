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
		if (!(bpf_map__map_flags(map) & BPF_F_MMAPABLE))
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
		    (bpf_map__map_flags(map) & BPF_F_MMAPABLE))
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
		    !(bpf_map__map_flags(map) & BPF_F_MMAPABLE))
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
		    !(bpf_map__map_flags(map) & BPF_F_MMAPABLE))
			continue;

		if (bpf_map__map_flags(map) & BPF_F_RDONLY_PROG)
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
			    (bpf_map__map_flags(map) & BPF_F_MMAPABLE)) {
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
			obj->skeleton = s;				    \n\
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
	return err;
}

struct btfgen_member {
	struct btf_member *member;
	int idx;
};

struct btfgen_type {
	struct btf_type *type;
	unsigned int id;
	bool all_members;

	struct hashmap *members;
};

struct btfgen_info {
	struct hashmap *types;
	struct btf *src_btf;
};

static size_t btfgen_hash_fn(const void *key, void *ctx)
{
	return (size_t)key;
}

static bool btfgen_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

static void *uint_as_hash_key(int x)
{
	return (void *)(uintptr_t)x;
}

static void *u32_as_hash_key(__u32 x)
{
	return (void *)(uintptr_t)x;
}

static void btfgen_free_type(struct btfgen_type *type)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (!type)
		return;

	if (!IS_ERR_OR_NULL(type->members)) {
		hashmap__for_each_entry(type->members, entry, bkt) {
			free(entry->value);
		}
		hashmap__free(type->members);
	}

	free(type);
}

static void btfgen_free_info(struct btfgen_info *info)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (!info)
		return;

	if (!IS_ERR_OR_NULL(info->types)) {
		hashmap__for_each_entry(info->types, entry, bkt) {
			btfgen_free_type(entry->value);
		}
		hashmap__free(info->types);
	}

	btf__free(info->src_btf);

	free(info);
}

static struct btfgen_info *
btfgen_new_info(const char *targ_btf_path)
{
	struct btfgen_info *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	info->src_btf = btf__parse(targ_btf_path, NULL);
	if (libbpf_get_error(info->src_btf)) {
		btfgen_free_info(info);
		return NULL;
	}

	info->types = hashmap__new(btfgen_hash_fn, btfgen_equal_fn, NULL);
	if (IS_ERR(info->types)) {
		errno = -PTR_ERR(info->types);
		btfgen_free_info(info);
		return NULL;
	}

	return info;
}

static int btfgen_add_member(struct btfgen_type *btfgen_type,
			     struct btf_member *btf_member, int idx)
{
	struct btfgen_member *btfgen_member;
	int err;

	/* create new members hashmap for this btfgen type if needed */
	if (!btfgen_type->members) {
		btfgen_type->members = hashmap__new(btfgen_hash_fn, btfgen_equal_fn, NULL);
		if (IS_ERR(btfgen_type->members))
			return PTR_ERR(btfgen_type->members);
	}

	btfgen_member = calloc(1, sizeof(*btfgen_member));
	if (!btfgen_member)
		return -ENOMEM;
	btfgen_member->member = btf_member;
	btfgen_member->idx = idx;
	/* add btf_member as member to given btfgen_type */
	err = hashmap__add(btfgen_type->members, uint_as_hash_key(btfgen_member->idx),
			   btfgen_member);
	if (err) {
		free(btfgen_member);
		if (err != -EEXIST)
			return err;
	}

	return 0;
}

static struct btfgen_type *btfgen_get_type(struct btfgen_info *info, int id)
{
	struct btfgen_type *type = NULL;

	hashmap__find(info->types, uint_as_hash_key(id), (void **)&type);

	return type;
}

static struct btfgen_type *
_btfgen_put_type(struct btf *btf, struct btfgen_info *info, struct btf_type *btf_type,
		 unsigned int id, bool all_members)
{
	struct btfgen_type *btfgen_type, *tmp;
	struct btf_array *array;
	unsigned int child_id;
	struct btf_member *m;
	int err, i, n;

	/* check if we already have this type */
	if (hashmap__find(info->types, uint_as_hash_key(id), (void **) &btfgen_type)) {
		if (!all_members || btfgen_type->all_members)
			return btfgen_type;
	} else {
		btfgen_type = calloc(1, sizeof(*btfgen_type));
		if (!btfgen_type)
			return NULL;

		btfgen_type->type = btf_type;
		btfgen_type->id = id;

		/* append this type to the types list before anything else */
		err = hashmap__add(info->types, uint_as_hash_key(btfgen_type->id), btfgen_type);
		if (err) {
			free(btfgen_type);
			return NULL;
		}
	}

	/* avoid infinite recursion and yet be able to add all
	 * fields/members for types also managed by this function
	 */
	btfgen_type->all_members = all_members;


	/* recursively add other types needed by it */
	switch (btf_kind(btfgen_type->type)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		/* doesn't need resolution if not adding all members */
		if (!all_members)
			break;

		n = btf_vlen(btf_type);
		m = btf_members(btf_type);
		for (i = 0; i < n; i++, m++) {
			btf_type = (struct btf_type *) btf__type_by_id(btf, m->type);

			/* add all member types */
			tmp = _btfgen_put_type(btf, info, btf_type, m->type, all_members);
			if (!tmp)
				return NULL;

			/* add all members */
			err = btfgen_add_member(btfgen_type, m, i);
			if (err)
				return NULL;
		}
		break;
	case BTF_KIND_PTR:
		if (!all_members)
			break;
	/* fall through */
	/* Also add the type it's pointing to when adding all members */
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		child_id = btf_type->type;
		btf_type = (struct btf_type *) btf__type_by_id(btf, child_id);

		tmp = _btfgen_put_type(btf, info, btf_type, child_id, all_members);
		if (!tmp)
			return NULL;
		break;
	case BTF_KIND_ARRAY:
		array = btf_array(btfgen_type->type);

		/* add type for array type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
		tmp = _btfgen_put_type(btf, info, btf_type, array->type, all_members);
		if (!tmp)
			return NULL;

		/* add type for array's index type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->index_type);
		tmp = _btfgen_put_type(btf, info, btf_type, array->index_type, all_members);
		if (!tmp)
			return NULL;
		break;
	/* tells if some other type needs to be handled */
	default:
		p_err("unsupported kind: %s (%d)",
		      btf_kind_str(btfgen_type->type), btfgen_type->id);
		errno = EINVAL;
		return NULL;
	}

	return btfgen_type;
}

/* Put type in the list. If the type already exists it's returned, otherwise a
 * new one is created and added to the list. This is called recursively adding
 * all the types that are needed for the current one.
 */
static struct btfgen_type *
btfgen_put_type(struct btf *btf, struct btfgen_info *info, struct btf_type *btf_type,
		unsigned int id)
{
	return _btfgen_put_type(btf, info, btf_type, id, false);
}

/* Same as btfgen_put_type, but adding all members, from given complex type, recursively */
static struct btfgen_type *
btfgen_put_type_all(struct btf *btf, struct btfgen_info *info,
		    struct btf_type *btf_type, unsigned int id)
{
	return _btfgen_put_type(btf, info, btf_type, id, true);
}

static int btfgen_record_field_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = (struct btf *) info->src_btf;
	struct btfgen_type *btfgen_type;
	struct btf_member *btf_member;
	struct btf_type *btf_type;
	struct btf_array *array;
	unsigned int id;
	int idx, err;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	/* create btfgen_type for root type */
	btfgen_type = btfgen_put_type(btf, info, btf_type, targ_spec->root_type_id);
	if (!btfgen_type)
		return -errno;

	/* add types for complex types (arrays, unions, structures) */
	for (int i = 1; i < targ_spec->raw_len; i++) {
		/* skip typedefs and mods */
		while (btf_is_mod(btf_type) || btf_is_typedef(btf_type)) {
			id = btf_type->type;
			btfgen_type = btfgen_get_type(info, id);
			if (!btfgen_type)
				return -ENOENT;
			btf_type = (struct btf_type *) btf__type_by_id(btf, id);
		}

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			idx = targ_spec->raw_spec[i];
			btf_member = btf_members(btf_type) + idx;
			btf_type = (struct btf_type *) btf__type_by_id(btf, btf_member->type);

			/* add member to relocation type */
			err = btfgen_add_member(btfgen_type, btf_member, idx);
			if (err)
				return err;
			/* put btfgen type */
			btfgen_type = btfgen_put_type(btf, info, btf_type, btf_member->type);
			if (!btfgen_type)
				return -errno;
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			btfgen_type = btfgen_get_type(info, array->type);
			if (!btfgen_type)
				return -ENOENT;
			btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
			break;
		default:
			p_err("spec type wasn't handled");
			return -EINVAL;
		}
	}

	return 0;
}

static int btfgen_record_type_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = (struct btf *) info->src_btf;
	struct btfgen_type *btfgen_type;
	struct btf_type *btf_type;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	btfgen_type = btfgen_put_type_all(btf, info, btf_type, targ_spec->root_type_id);
	return btfgen_type ?  0 : -errno;
}

static int btfgen_record_enumval_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = (struct btf *) info->src_btf;
	struct btfgen_type *btfgen_type;
	struct btf_type *btf_type;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	btfgen_type = btfgen_put_type_all(btf, info, btf_type, targ_spec->root_type_id);
	return btfgen_type ?  0 : -errno;
}

static int btfgen_record_reloc(struct btfgen_info *info, struct bpf_core_spec *res)
{
	switch (res->relo_kind) {
	case BPF_CORE_FIELD_BYTE_OFFSET:
	case BPF_CORE_FIELD_BYTE_SIZE:
	case BPF_CORE_FIELD_EXISTS:
	case BPF_CORE_FIELD_SIGNED:
	case BPF_CORE_FIELD_LSHIFT_U64:
	case BPF_CORE_FIELD_RSHIFT_U64:
		return btfgen_record_field_relo(info, res);
	case BPF_CORE_TYPE_ID_LOCAL:
	case BPF_CORE_TYPE_ID_TARGET:
	case BPF_CORE_TYPE_EXISTS:
	case BPF_CORE_TYPE_SIZE:
		return btfgen_record_type_relo(info, res);
	case BPF_CORE_ENUMVAL_EXISTS:
	case BPF_CORE_ENUMVAL_VALUE:
		return btfgen_record_enumval_relo(info, res);
	default:
		return -EINVAL;
	}
}

static struct bpf_core_cand_list *
btfgen_find_cands(const struct btf *local_btf, const struct btf *targ_btf, __u32 local_id)
{
	const struct btf_type *local_type;
	struct bpf_core_cand_list *cands = NULL;
	struct bpf_core_cand local_cand = {};
	size_t local_essent_len;
	const char *local_name;
	int err;

	local_cand.btf = local_btf;
	local_cand.id = local_id;

	local_type = btf__type_by_id(local_btf, local_id);
	if (!local_type) {
		err = -EINVAL;
		goto err_out;
	}

	local_name = btf__name_by_offset(local_btf, local_type->name_off);
	if (!local_name) {
		err = -EINVAL;
		goto err_out;
	}
	local_essent_len = bpf_core_essential_name_len(local_name);

	cands = calloc(1, sizeof(*cands));
	if (!cands)
		return NULL;

	err = bpf_core_add_cands(&local_cand, local_essent_len, targ_btf, "vmlinux", 1, cands);
	if (err)
		goto err_out;

	return cands;

err_out:
	if (cands)
		bpf_core_free_cands(cands);
	errno = -err;
	return NULL;
}

/* Record relocation information for a single BPF object*/
static int btfgen_record_obj(struct btfgen_info *info, const char *obj_path)
{
	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *relo;
	const struct btf_ext_info *seg;
	struct hashmap *cand_cache;
	struct btf_ext *btf_ext;
	unsigned int relo_idx;
	struct btf *btf;
	int err;

	btf = btf__parse(obj_path, &btf_ext);
	err = libbpf_get_error(btf);
	if (err) {
		p_err("failed to parse bpf object '%s': %s", obj_path, strerror(errno));
		return err;
	}

	if (btf_ext->core_relo_info.len == 0)
		return 0;

	cand_cache = bpf_core_create_cand_cache();
	if (IS_ERR(cand_cache))
		return PTR_ERR(cand_cache);

	seg = &btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec) {
		for_each_btf_ext_rec(seg, sec, relo_idx, relo) {
			struct bpf_core_spec specs_scratch[3] = {};
			struct bpf_core_relo_res targ_res = {};
			struct bpf_core_cand_list *cands = NULL;
			const void *type_key = u32_as_hash_key(relo->type_id);
			const char *sec_name = btf__name_by_offset(btf, sec->sec_name_off);

			if (relo->kind != BPF_CORE_TYPE_ID_LOCAL &&
			    !hashmap__find(cand_cache, type_key, (void **)&cands)) {
				cands = btfgen_find_cands(btf, info->src_btf, relo->type_id);
				if (!cands) {
					err = -errno;
					goto out;
				}

				err = hashmap__set(cand_cache, type_key, cands, NULL, NULL);
				if (err)
					goto out;
			}

			err = bpf_core_calc_relo_insn(sec_name, relo, relo_idx, btf, cands,
						      specs_scratch, &targ_res);
			if (err)
				goto out;

			err = btfgen_record_reloc(info, &specs_scratch[2]);
			if (err)
				goto out;
		}
	}

out:
	bpf_core_free_cand_cache(cand_cache);

	return err;
}

/* Generate BTF from relocation information previously recorded */
static struct btf *btfgen_get_btf(struct btfgen_info *info)
{
	return ERR_PTR(-EOPNOTSUPP);
}

/* Create BTF file for a set of BPF objects.
 *
 * The BTFGen algorithm is divided in two main parts: (1) collect the
 * BTF types that are involved in relocations and (2) generate the BTF
 * object using the collected types.
 *
 * In order to collect the types involved in the relocations, we parse
 * the BTF and BTF.ext sections of the BPF objects and use
 * bpf_core_calc_relo_insn() to get the target specification, this
 * indicates how the types and fields are used in a relocation.
 *
 * Types are recorded in different ways according to the kind of the
 * relocation. For field-based relocations only the members that are
 * actually used are saved in order to reduce the size of the generated
 * BTF file. For type-based and enum-based relocations the whole type is
 * saved.
 *
 * The second part of the algorithm generates the BTF object. It creates
 * an empty BTF object and fills it with the types recorded in the
 * previous step. This function takes care of only adding the structure
 * and union members that were marked as used and it also fixes up the
 * type IDs on the generated BTF object.
 */
static int btfgen(const char *src_btf, const char *dst_btf, const char *objspaths[])
{
	struct btfgen_info *info;
	struct btf *btf_new = NULL;
	int err;

	info = btfgen_new_info(src_btf);
	if (!info) {
		p_err("failed to allocate info structure: %s", strerror(errno));
		err = -errno;
		goto out;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("OBJ : %s\n", objspaths[i]);

		err = btfgen_record_obj(info, objspaths[i]);
		if (err)
			goto out;
	}

	btf_new = btfgen_get_btf(info);
	if (!btf_new) {
		err = -errno;
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
	btf__free(btf_new);
	btfgen_free_info(info);

	return err;
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

	/* single BTF file */
	if (input_is_file) {
		printf("SBTF: %s\n", input);

		if (output_is_file) {
			err = btfgen(input, output, objs);
			goto out;
		}
		snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", output,
			 basename(input));
		err = btfgen(input, dst_btf_path, objs);
		goto out;
	}

	if (output_is_file) {
		p_err("can't have just one file as output");
		err = -EINVAL;
		goto out;
	}

	/* directory with BTF files */
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

		err = btfgen(src_btf_path, dst_btf_path, objs);
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
