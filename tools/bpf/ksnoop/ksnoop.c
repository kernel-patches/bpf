// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "ksnoop.h"
#include "ksnoop.skel.h"

struct btf *vmlinux_btf;
const char *bin_name;
int pages = PAGES_DEFAULT;

enum log_level {
	DEBUG,
	WARN,
	ERROR,
};

enum log_level log_level = WARN;

__u32 filter_pid;
bool stack_mode;

#define libbpf_errstr(val)	strerror(-libbpf_get_error(val))

static void __p(enum log_level level, char *level_str, char *fmt, ...)
{
	va_list ap;

	if (level < log_level)
		return;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", level_str);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#define p_err(fmt, ...)		__p(ERROR, "Error", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...)	__p(WARNING, "Warn", fmt, ##__VA_ARGS__)
#define	p_debug(fmt, ...)	__p(DEBUG, "Debug", fmt, ##__VA_ARGS__)

static int do_version(int argc, char **argv)
{
	printf("%s v%s\n", bin_name, KSNOOP_VERSION);
	return 0;
}

static int cmd_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [COMMAND | help] FUNC\n"
		"	COMMAND	:= { trace | info }\n"
		"	FUNC	:= { name | name(ARG[,ARG]*) }\n"
		"	ARG	:= { arg | arg->member }\n"
		"	OPTIONS	:= { {-d|--debug} | {-V|--version} |\n"
		"                    {-p|--pid filter_pid}|\n"
		"                    {-P|--pages nr_pages} }\n"
		"                    {-s|--stack}\n",
		bin_name);
	fprintf(stderr,
		"Examples:\n"
		"	%s info ip_send_skb\n"
		"	%s trace ip_send_skb\n"
		"	%s trace \"ip_send_skb(skb, return)\"\n"
		"	%s trace \"ip_send_skb(skb->sk, return))\"\n",
		bin_name, bin_name, bin_name, bin_name);
	return 0;
}

static void usage(void)
{
	cmd_help(0, NULL);
	exit(1);
}

static void type_to_value(struct btf *btf, char *name, __u32 type_id,
			  struct value *val)
{
	const struct btf_type *type;
	__s32 id = type_id;

	if (strlen(val->name) == 0) {
		if (name)
			strncpy(val->name, name,
				sizeof(val->name));
		else
			val->name[0] = '\0';
	}
	do {
		type = btf__type_by_id(btf, id);

		switch (BTF_INFO_KIND(type->info)) {
		case BTF_KIND_CONST:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
			id = type->type;
			break;
		case BTF_KIND_PTR:
			val->flags |= KSNOOP_F_PTR;
			id = type->type;
			break;
		default:
			val->type_id = id;
			goto done;
		}
	} while (id >= 0);

	val->type_id = KSNOOP_ID_UNKNOWN;
	return;
done:
	val->size = btf__resolve_size(btf, val->type_id);
}

static int member_to_value(struct btf *btf, const char *name, __u32 type_id,
			   struct value *val, int lvl)
{
	const struct btf_member *member;
	const struct btf_type *type;
	const char *pname;
	__s32 id = type_id;
	int i, nmembers;
	__u8 kind;

	/* type_to_value has already stripped qualifiers, so
	 * we either have a base type, a struct, union, etc.
	 * Only struct/unions have named members so anything
	 * else is invalid.
	 */
	p_debug("Looking for member '%s' in type id %d", name, type_id);
	type = btf__type_by_id(btf, id);
	pname = btf__str_by_offset(btf, type->name_off);
	if (strlen(pname) == 0)
		pname = "<anon>";

	kind = BTF_INFO_KIND(type->info);
	switch (kind) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		nmembers = BTF_INFO_VLEN(type->info);
		p_debug("Checking %d members...", nmembers);
		for (member = (struct btf_member *)(type + 1), i = 0;
		     i < nmembers;
		     member++, i++) {
			const char *mname;
			__u16 offset;

			type = btf__type_by_id(btf, member->type);
			mname = btf__str_by_offset(btf, member->name_off);
			offset = member->offset / 8;

			p_debug("Checking member '%s' type %d offset %d",
				mname, member->type, offset);

			/* anonymous struct member? */
			kind = BTF_INFO_KIND(type->info);
			if (strlen(mname) == 0 &&
			    (kind == BTF_KIND_STRUCT ||
			     kind == BTF_KIND_UNION)) {
				p_debug("Checking anon struct/union %d",
					member->type);
				val->offset += offset;
				if (!member_to_value(btf, name, member->type,
						     val, lvl + 1))
					return 0;
				val->offset -= offset;
				continue;
			}

			if (strcmp(mname, name) == 0) {
				val->offset += offset;
				val->flags = KSNOOP_F_MEMBER;
				type_to_value(btf, NULL, member->type, val);
				p_debug("Member '%s', offset %d, flags %x",
					mname, val->offset, val->flags);
				return 0;
			}
		}
		if (lvl > 0)
			break;
		p_err("No member '%s' found in %s [%d], offset %d", name, pname,
		      id, val->offset);
		break;
	default:
		p_err("'%s' is not a struct/union", pname);
		break;
	}
	return -ENOENT;
}

static int get_func_btf(struct btf *btf, struct func *func)
{
	const struct btf_param *param;
	const struct btf_type *type;
	__u8 i;

	func->id = btf__find_by_name_kind(btf, func->name, BTF_KIND_FUNC);
	if (func->id <= 0) {
		p_err("Cannot find function '%s' in BTF: %s",
		       func->name, strerror(-func->id));
		return -ENOENT;
	}
	type = btf__type_by_id(btf, func->id);
	if (libbpf_get_error(type) ||
	    BTF_INFO_KIND(type->info) != BTF_KIND_FUNC) {
		p_err("Error looking up function type via id '%d'", func->id);
		return -EINVAL;
	}
	type = btf__type_by_id(btf, type->type);
	if (libbpf_get_error(type) ||
	    BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO) {
		p_err("Error looking up function proto type via id '%d'",
		      func->id);
		return -EINVAL;
	}
	for (param = (struct btf_param *)(type + 1), i = 0;
	     i < BTF_INFO_VLEN(type->info) && i < MAX_ARGS;
	     param++, i++) {
		type_to_value(btf,
			      (char *)btf__str_by_offset(btf, param->name_off),
			      param->type, &func->args[i]);
		p_debug("arg #%d: <name '%s', type id '%u'>",
			i + 1, func->args[i].name, func->args[i].type_id);
	}

	/* real number of args, even if it is > number we recorded. */
	func->nr_args = BTF_INFO_VLEN(type->info);

	type_to_value(btf, KSNOOP_RETURN_NAME, type->type,
		      &func->args[KSNOOP_RETURN]);
	p_debug("return value: type id '%u'>",
		func->args[KSNOOP_RETURN].type_id);
	return 0;
}

static int trace_to_value(struct btf *btf, struct func *func, char *argname,
			  char *membername, struct value *val)
{
	__u8 i;

	strncpy(val->name, argname, sizeof(val->name));
	if (strlen(membername) > 0) {
		strncat(val->name, "->", sizeof(val->name));
		strncat(val->name, membername, sizeof(val->name));
	}

	for (i = 0; i < MAX_TRACES; i++) {
		if (!func->args[i].name)
			continue;
		if (strcmp(argname, func->args[i].name) != 0)
			continue;
		p_debug("setting base arg for val %s to %d", val->name, i);
		val->base_arg = i;

		if (strlen(membername) > 0) {
			if (member_to_value(btf, membername,
					    func->args[i].type_id, val, 0))
				return -ENOENT;
		} else {
			val->type_id = func->args[i].type_id;
			val->flags |= func->args[i].flags;
			val->size = func->args[i].size;
		}
	}
	return 0;
}

static struct btf *get_btf(const char *name)
{
	struct btf *mod_btf;
	char path[MAX_STR];

	p_debug("getting BTF for %s",
		name && strlen(name) > 0 ? name : "vmlinux");

	if (!vmlinux_btf) {
		vmlinux_btf = libbpf_find_kernel_btf();
		if (libbpf_get_error(vmlinux_btf)) {
			p_err("No BTF, cannot determine type info: %s",
			      libbpf_errstr(vmlinux_btf));
			return NULL;
		}
	}
	if (!name || strlen(name) == 0)
		return vmlinux_btf;

	snprintf(path, sizeof(path), "/sys/kernel/btf/%s", name);

	mod_btf = btf__parse_raw_split(path, vmlinux_btf);
	if (libbpf_get_error(mod_btf)) {
		p_err("No BTF for module '%s': %s",
		      name, libbpf_errstr(mod_btf));
		return NULL;
	}
	return mod_btf;
}

static void copy_without_spaces(char *target, char *src)
{
	for (; *src != '\0'; src++)
		if (!isspace(*src))
			*(target++) = *src;
	*target = '\0';
}

static char *type_id_to_str(struct btf *btf, __s32 type_id, char *str)
{
	const struct btf_type *type;
	const char *name = "";
	char *prefix = "";
	char *suffix = " ";
	char *ptr = "";

	str[0] = '\0';

	switch (type_id) {
	case 0:
		name = "void";
		break;
	case KSNOOP_ID_UNKNOWN:
		name = "?";
		break;
	default:
		do {
			type = btf__type_by_id(btf, type_id);

			if (libbpf_get_error(type)) {
				name = "?";
				break;
			}
			switch (BTF_INFO_KIND(type->info)) {
			case BTF_KIND_CONST:
			case BTF_KIND_VOLATILE:
			case BTF_KIND_RESTRICT:
				type_id = type->type;
				break;
			case BTF_KIND_PTR:
				ptr = "* ";
				type_id = type->type;
				break;
			case BTF_KIND_ARRAY:
				suffix = "[]";
				type_id = type->type;
				break;
			case BTF_KIND_STRUCT:
				prefix = "struct ";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_UNION:
				prefix = "union";
				name = btf__str_by_offset(btf, type->name_off);
				break;
			case BTF_KIND_ENUM:
				prefix = "enum ";
				break;
			case BTF_KIND_TYPEDEF:
				name = btf__str_by_offset(btf, type->name_off);
				break;
			default:
				name = btf__str_by_offset(btf, type->name_off);
				break;
			}
		} while (type_id >= 0 && strlen(name) == 0);
		break;
	}
	snprintf(str, MAX_STR, "%s%s%s%s", prefix, name, suffix, ptr);

	return str;
}

static char *value_to_str(struct btf *btf, struct value *val, char *str)
{

	str = type_id_to_str(btf, val->type_id, str);
	if (val->flags & KSNOOP_F_PTR)
		strncat(str, " * ", MAX_STR);
	if (strlen(val->name) > 0 &&
	    strcmp(val->name, KSNOOP_RETURN_NAME) != 0)
		strncat(str, val->name, MAX_STR);

	return str;
}

/* based heavily on bpf_object__read_kallsyms_file() in libbpf.c */
static int get_func_ip_mod(struct func *func)
{
	char sym_type, sym_name[MAX_STR], mod_info[MAX_STR];
	unsigned long long sym_addr;
	int ret, err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		err = errno;
		p_err("failed to open /proc/kallsyms: %d", strerror(err));
		return err;
	}

	while (true) {
		ret = fscanf(f, "%llx %c %128s%[^\n]\n",
			     &sym_addr, &sym_type, sym_name, mod_info);
		if (ret == EOF && feof(f))
			break;
		if (ret < 3) {
			p_err("failed to read kallsyms entry: %d", ret);
			err = -EINVAL;
			goto out;
		}
		if (strcmp(func->name, sym_name) != 0)
			continue;
		func->ip = sym_addr;
		func->mod[0] = '\0';
		/* get module name from [modname] */
		if (ret == 4) {
			if (sscanf(mod_info, "%*[\t ]\[%[^]]", func->mod) < 1) {
				p_err("failed to read module name");
				err = -EINVAL;
				goto out;
			}
		}
		p_debug("%s =  <ip %llx, mod %s>", func->name, func->ip,
			strlen(func->mod) > 0 ? func->mod : "vmlinux");
		break;
	}
out:
	fclose(f);
	return err;
}

static void trace_printf(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

#define VALID_NAME	"%[A-Za-z0-9\\-_]"
#define ARGDATA		"%[^)]"

static int parse_trace(char *str, struct trace *trace)
{
	struct btf_dump_opts opts = { };
	struct func *func = &trace->func;
	char tracestr[MAX_STR], argdata[MAX_STR];
	char argname[MAX_STR], membername[MAX_STR];
	char *arg, *saveptr;
	int ret;
	__u8 i;

	copy_without_spaces(tracestr, str);

	p_debug("Parsing trace '%s'", tracestr);

	trace->filter_pid = (__u32)filter_pid;
	if (filter_pid)
		p_debug("Using pid %lu as filter", trace->filter_pid);

	trace->btf = vmlinux_btf;

	ret = sscanf(tracestr, VALID_NAME "(" ARGDATA ")", func->name, argdata);
	if (ret <= 0)
		usage();
	if (ret == 1) {
		if (strlen(tracestr) > strlen(func->name)) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		argdata[0] = '\0';
		p_debug("got func '%s'", func->name);
	} else {
		if (strlen(tracestr) >
		    strlen(func->name) + strlen(argdata) + 2) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		p_debug("got func '%s', args '%s'", func->name, argdata);
		trace->flags |= KSNOOP_F_CUSTOM;
	}

	ret = get_func_ip_mod(func);
	if (ret) {
		p_err("could not get address of '%s'", func->name);
		return ret;
	}
	trace->btf = get_btf(func->mod);
	if (libbpf_get_error(trace->btf)) {
		p_err("could not get BTF for '%s': %s",
		      strlen(func->mod) ? func->mod : "vmlinux",
		      libbpf_errstr(trace->btf));
		return -ENOENT;
	}
	trace->dump = btf_dump__new(trace->btf, NULL, &opts, trace_printf);
	if (libbpf_get_error(trace->dump)) {
		p_err("could not create BTF dump : %n",
		      libbpf_errstr(trace->btf));
		return -EINVAL;
	}

	ret = get_func_btf(trace->btf, func);
	if (ret) {
		p_debug("unexpected return value '%d' getting function", ret);
		return ret;
	}

	for (arg = strtok_r(argdata, ",", &saveptr), i = 0;
	     arg;
	     arg = strtok_r(NULL, ",", &saveptr), i++) {
		ret = sscanf(arg, VALID_NAME "->" VALID_NAME,
			     argname, membername);
		if (ret == 2) {
			if (strlen(arg) >
			    strlen(argname) + strlen(membername) + 2) {
				p_err("Invalid argument specification '%s'",
				      arg);
				usage();
			}
			p_debug("'%s' dereferences '%s'", argname, membername);
		} else {
			if (strlen(arg) > strlen(argname)) {
				p_err("Invalid argument specification '%s'",
				      arg);
				usage();
			}
			p_debug("'%s' arg", argname);
			membername[0] = '\0';
		}

		if (i >= MAX_TRACES) {
			p_err("Too many arguments; up to %d are supported",
			      MAX_TRACES);
			return -EINVAL;
		}
		if (trace_to_value(trace->btf, func, argname, membername,
				   &trace->traces[i]))
			return -EINVAL;

		trace->nr_traces++;
	}

	if (trace->nr_traces > 0) {
		trace->flags |= KSNOOP_F_CUSTOM;
		p_debug("custom trace with %d args", trace->nr_traces);
	} else {
		p_debug("Standard trace, function with %d arguments",
			func->nr_args);
		/* copy function arg/return value to trace specification. */
		memcpy(trace->traces, func->args, sizeof(trace->traces));
		for (i = 0; i < MAX_TRACES; i++)
			trace->traces[i].base_arg = i;
		trace->nr_traces = MAX_TRACES;
	}

	return 0;
}

static int parse_traces(int argc, char **argv, struct trace **traces)
{
	__u8 i;

	if (argc == 0)
		usage();

	if (argc > MAX_FUNC_TRACES) {
		p_err("A maximum of %d traces are supported", MAX_FUNC_TRACES);
		return -EINVAL;
	}
	*traces = calloc(argc, sizeof(struct trace));
	if (!*traces) {
		p_err("Could not allocate %d traces", argc);
		return -ENOMEM;
	}
	for (i = 0; i < argc; i++) {
		if (parse_trace(argv[i], &((*traces)[i])))
			return -EINVAL;
		if (!stack_mode || i == 0)
			continue;
		/* tell stack mode trace which function to expect next */
		(*traces)[i].prev_ip = (*traces)[i-1].func.ip;
		(*traces)[i-1].next_ip = (*traces)[i].func.ip;
	}
	return i;
}

static int cmd_info(int argc, char **argv)
{
	struct trace *traces;
	char str[MAX_STR];
	int nr_traces;
	__u8 i, j;

	nr_traces = parse_traces(argc, argv, &traces);
	if (nr_traces < 0)
		return nr_traces;

	for (i = 0; i < nr_traces; i++) {
		struct func *func = &traces[i].func;

		printf("%s %s(",
		       value_to_str(traces[i].btf, &func->args[KSNOOP_RETURN],
				    str),
		       func->name);
		for (j = 0; j < func->nr_args; j++) {
			if (j > 0)
				printf(", ");
			printf("%s", value_to_str(traces[i].btf, &func->args[j],
						  str));
		}
		if (func->nr_args > MAX_ARGS)
			printf(" /* and %d more args that are not traceable */",
			       func->nr_args - MAX_ARGS);
		printf(");\n");
	}
	return 0;
}

static void trace_handler(void *ctx, int cpu, void *data, __u32 size)
{
	struct trace *trace = data;
	int i, shown, ret;

	p_debug("got trace, size %d", size);
	if (size < (sizeof(*trace) - MAX_TRACE_BUF)) {
		p_err("\t/* trace buffer size '%u' < min %ld */",
			size, sizeof(trace) - MAX_TRACE_BUF);
		return;
	}
	printf("%16lld %4d %8u %s(\n", trace->time, trace->cpu, trace->pid,
	       trace->func.name);

	for (i = 0, shown = 0; i < trace->nr_traces; i++) {
		DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts);
		bool entry = trace->data_flags & KSNOOP_F_ENTRY;

		opts.indent_level = 36;
		opts.indent_str = " ";

		if ((entry && !base_arg_is_entry(trace->traces[i].base_arg)) ||
		    (!entry && base_arg_is_entry(trace->traces[i].base_arg)))
			continue;

		if (trace->traces[i].type_id == 0)
			continue;

		if (shown > 0)
			printf(",\n");
		printf("%34s %s = ", "", trace->traces[i].name);
		if (trace->traces[i].flags & KSNOOP_F_PTR)
			printf("*(0x%llx)", trace->trace_data[i].raw_value);
		printf("\n");

		if (trace->trace_data[i].err_type_id != 0) {
			char typestr[MAX_STR];

			printf("%36s /* Cannot show '%s' as '%s%s'; null/userspace ptr? */\n",
			       "",
			       trace->traces[i].name,
			       type_id_to_str(trace->btf,
					      trace->traces[i].type_id,
					      typestr),
			       trace->traces[i].flags & KSNOOP_F_PTR ?
			       " *" : "");
		} else {
			ret = btf_dump__dump_type_data
				(trace->dump, trace->traces[i].type_id,
				 trace->buf + trace->trace_data[i].buf_offset,
				 trace->trace_data[i].buf_len, &opts);
			/* truncated? */
			if (ret == -E2BIG)
				printf("%36s...", "");
		}
		shown++;

	}
	printf("\n%31s);\n\n", "");
}

static void lost_handler(void *ctx, int cpu, __u64 cnt)
{
	p_err("\t/* lost %llu events */", cnt);
}

static int add_traces(struct bpf_map *func_map, struct trace *traces,
		      int nr_traces)
{
	int i, j, ret, nr_cpus = libbpf_num_possible_cpus();
	struct trace *map_traces;

	map_traces = calloc(nr_cpus, sizeof(struct trace));
	if (!map_traces) {
		p_err("Could not allocate memory for %d traces", nr_traces);
		return -ENOMEM;
	}
	for (i = 0; i < nr_traces; i++) {
		for (j = 0; j < nr_cpus; j++)
			memcpy(&map_traces[j], &traces[i],
			       sizeof(map_traces[j]));

		ret = bpf_map_update_elem(bpf_map__fd(func_map),
					  &traces[i].func.ip,
					  map_traces,
					  BPF_NOEXIST);
		if (ret) {
			p_err("Could not add map entry for '%s': %s",
			      traces[i].func.name, strerror(-ret));
			return ret;
		}
	}
	return 0;
}

static int attach_traces(struct ksnoop_bpf *skel, struct trace *traces,
			 int nr_traces)
{
	struct bpf_object *obj = skel->obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	int i, ret;

	for (i = 0; i < nr_traces; i++) {
		bpf_object__for_each_program(prog, obj) {
			const char *sec_name = bpf_program__section_name(prog);
			bool kretprobe = strstr(sec_name, "kretprobe/") != NULL;

			link = bpf_program__attach_kprobe(prog, kretprobe,
							  traces[i].func.name);
			ret = libbpf_get_error(link);
			if (ret) {
				p_err("Could not attach %s to '%s': %s",
				      kretprobe ? "kretprobe" : "kprobe",
				      traces[i].func.name,
				      strerror(-ret));
				return ret;
			}
			p_debug("Attached %s for '%s'",
				kretprobe ? "kretprobe" : "kprobe",
				traces[i].func.name);
		}
	}
	return 0;
}

static int cmd_trace(int argc, char **argv)
{
	struct perf_buffer_opts pb_opts = {};
	struct bpf_map *perf_map, *func_map;
	struct perf_buffer *pb;
	struct ksnoop_bpf *skel;
	struct trace *traces;
	int nr_traces, ret;

	nr_traces = parse_traces(argc, argv, &traces);
	if (nr_traces < 0)
		return nr_traces;

	skel = ksnoop_bpf__open_and_load();
	if (!skel) {
		p_err("Could not load ksnoop BPF: %s", libbpf_errstr(skel));
		return 1;
	}

	perf_map = bpf_object__find_map_by_name(skel->obj, "ksnoop_perf_map");
	if (!perf_map) {
		p_err("Could not find '%s'", "ksnoop_perf_map");
		return 1;
	}
	func_map = bpf_object__find_map_by_name(skel->obj, "ksnoop_func_map");
	if (!func_map) {
		p_err("Could not find '%s'", "ksnoop_func_map");
		return 1;
	}

	if (add_traces(func_map, traces, nr_traces)) {
		p_err("Could not add traces to '%s'", "ksnoop_func_map");
		return 1;
	}

	if (attach_traces(skel, traces, nr_traces)) {
		p_err("Could not attach %d traces", nr_traces);
		return 1;
	}

	pb_opts.sample_cb = trace_handler;
	pb_opts.lost_cb = lost_handler;
	pb = perf_buffer__new(bpf_map__fd(perf_map), pages, &pb_opts);
	if (libbpf_get_error(pb)) {
		p_err("Could not create perf buffer: %s",
		      libbpf_errstr(pb));
		return 1;
	}

	printf("%16s %4s %8s %s\n", "TIME", "CPU", "PID", "FUNCTION/ARGS");

	while (1) {
		ret = perf_buffer__poll(pb, 1);
		if (ret < 0 && ret != -EINTR) {
			p_err("Polling failed: %s", strerror(-ret));
			return 1;
		}
	}

	return 0;
}

struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};

struct cmd cmds[] = {
	{ "info",	cmd_info },
	{ "trace",	cmd_trace },
	{ "help",	cmd_help },
	{ NULL,		NULL }
};

static int cmd_select(int argc, char **argv)
{
	int i;

	for (i = 0; cmds[i].cmd; i++) {
		if (strncmp(*argv, cmds[i].cmd, strlen(*argv)) == 0)
			return cmds[i].func(argc - 1, argv + 1);
	}
	return cmd_trace(argc, argv);
}

static int print_all_levels(enum libbpf_print_level level,
		 const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "debug",	no_argument,		NULL,	'd' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "version",	no_argument,		NULL,	'V' },
		{ "pages",	required_argument,	NULL,	'P' },
		{ "pid",	required_argument,	NULL,	'p' },
		{ 0 }
	};
	int opt;

	bin_name = argv[0];

	while ((opt = getopt_long(argc, argv, "dhp:P:sV", options,
				  NULL)) >= 0) {
		switch (opt) {
		case 'd':
			libbpf_set_print(print_all_levels);
			log_level = DEBUG;
			break;
		case 'h':
			return cmd_help(argc, argv);
		case 'V':
			return do_version(argc, argv);
		case 'p':
			filter_pid = atoi(optarg);
			break;
		case 'P':
			pages = atoi(optarg);
			break;
		case 's':
			stack_mode = true;
			break;
		default:
			p_err("unrecognized option '%s'", argv[optind - 1]);
			usage();
		}
	}
	if (argc == 1)
		usage();
	argc -= optind;
	argv += optind;
	if (argc < 0)
		usage();

	return cmd_select(argc, argv);

	return 0;
}
