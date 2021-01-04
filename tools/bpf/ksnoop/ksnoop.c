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

void __p(enum log_level level, char *level_str, char *fmt, ...)
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

#define p_err(fmt, ...)		__p(ERROR, "Error", fmt, __VA_ARGS__)
#define p_warn(fmt, ...)	__p(WARNING, "Warn", fmt, __VA_ARGS__)
#define	p_debug(fmt, ...)	__p(DEBUG, "Debug", fmt, __VA_ARGS__)

int do_version(int argc, char **argv)
{
	printf("%s v%s\n", bin_name, KSNOOP_VERSION);
	return 0;
}

int cmd_help(int argc, char **argv)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] [COMMAND | help] FUNC\n"
		"	OPTIONS := { {-d|--debug} | {-V|--version} |\n"
		"		     {-p|--pages} }\n"
		"	COMMAND	:= { info | trace  }\n"
		"	FUNC	:= { name | name(ARG[,ARG]*) }\n"
		"	ARG	:= { arg | arg->member }\n",
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

void usage(void)
{
	cmd_help(0, NULL);
	exit(1);
}

void type_to_value(struct btf *btf, char *name, __u32 type_id,
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

	/* handle "void" type */
	if (type_id == 0) {
		val->type_id = type_id;
		val->size = 0;
		return;
	}

	val->type_id = KSNOOP_ID_UNKNOWN;

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
			val->size = sizeof(void *);
			id = type->type;
			break;
		case BTF_KIND_TYPEDEF:
			/* retain typedef type id, get size from target
			 * type.
			 */
			if (val->type_id == KSNOOP_ID_UNKNOWN)
				val->type_id = id;
			id = type->type;
			break;
		case BTF_KIND_ARRAY:
		case BTF_KIND_INT:
		case BTF_KIND_ENUM:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			/* size will be 0 for array; that's fine since
			 * we do not support predicates for arrays.
			 */
			if (!val->size)
				val->size = type->size;
			if (val->type_id == KSNOOP_ID_UNKNOWN)
				val->type_id = id;
			return;
		default:
			goto out;
		}
	} while (id >= 0);
out:
	val->type_id = KSNOOP_ID_UNKNOWN;
}

int member_to_value(struct btf *btf, const char *name, __u32 type_id,
		     struct value *val)

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
						     val))
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
		p_err("No member '%s' found in %s [%d], offset %d", name, pname,
		      id, val->offset);
		break;
	default:
		p_err("'%s' is not a struct/union", pname);
		break;
	}
	return -ENOENT;
}

int get_func_btf(struct btf *btf, struct func *func)
{
	const struct btf_param *param;
	const struct btf_type *type;
	__s32 id;
	__u8 i;

	id = btf__find_by_name_kind(btf, func->name, BTF_KIND_FUNC);
	if (id <= 0) {
		p_err("Cannot find function '%s' in BTF",
		       func->name);
		return -ENOENT;
	}
	type = btf__type_by_id(btf, id);
	if (libbpf_get_error(type) ||
	    BTF_INFO_KIND(type->info) != BTF_KIND_FUNC) {
		p_err("Error looking up function type via id '%d'", id);
		return -EINVAL;
	}
	type = btf__type_by_id(btf, type->type);
	if (libbpf_get_error(type) ||
	    BTF_INFO_KIND(type->info) != BTF_KIND_FUNC_PROTO) {
		p_err("Error looking up function proto type via id '%d'", id);
		return -EINVAL;
	}
	for (param = (struct btf_param *)(type + 1), i = 0;
	     i < BTF_INFO_VLEN(type->info) && i < MAX_ARGS;
	     param++, i++) {
		type_to_value(btf,
			      (char *)btf__str_by_offset(btf, param->name_off),
			      param->type, &func->args[i]);
		p_debug("arg #%d: <name '%s', type id '%u', size %d>",
			i + 1, func->args[i].name, func->args[i].type_id,
			func->args[i].size);
	}

	/* real number of args, even if it is > number we recorded. */
	func->nr_args = BTF_INFO_VLEN(type->info);

	type_to_value(btf, KSNOOP_RETURN_NAME, type->type,
		      &func->args[KSNOOP_RETURN]);
	p_debug("return value: type id '%u'>",
		func->args[KSNOOP_RETURN].type_id);
	return 0;
}

int predicate_to_value(char *predicate, struct value *val)
{
	char pred[MAX_STR], num[MAX_STR];
	char *endptr;

	if (!predicate)
		return 0;

	p_debug("checking predicate '%s' for '%s'", predicate, val->name);

	if (sscanf(predicate, "%[!=><]%[0-9]", pred, num) != 2) {
		p_err("Invalid specification; expected predicate, not '%s'",
		      predicate);
		return -EINVAL;
	}
	if (val->size == 0 || val->size > sizeof(__u64)) {
		p_err("'%s' (size %d) does not support predicate comparison",
		      val->name, val->size);
		return -EINVAL;
	}
	val->predicate_value = strtoull(num, &endptr, 0);

	if (strcmp(pred, "==") == 0) {
		val->flags |= KSNOOP_F_PREDICATE_EQ;
		goto out;
	} else if (strcmp(pred, "!=") == 0) {
		val->flags |= KSNOOP_F_PREDICATE_NOTEQ;
		goto out;
	}
	if (pred[0] == '>')
		val->flags |= KSNOOP_F_PREDICATE_GT;
	else if (pred[0] == '<')
		val->flags |= KSNOOP_F_PREDICATE_LT;

	if (strlen(pred) == 1)
		goto out;

	if (pred[1] != '=') {
		p_err("Invalid predicate specification '%s'", predicate);
		return -EINVAL;
	}
	val->flags |= KSNOOP_F_PREDICATE_EQ;

out:
	p_debug("predicate '%s', flags 0x%x value %x",
		predicate, val->flags, val->predicate_value);

	return 0;
}

int trace_to_value(struct btf *btf, struct func *func, char *argname,
		   char *membername, char *predicate, struct value *val)
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
					    func->args[i].type_id, val))
				return -ENOENT;
		} else {
			val->type_id = func->args[i].type_id;
			val->flags |= func->args[i].flags;
			val->size = func->args[i].size;
		}
		predicate_to_value(predicate, val);

		return 0;
	}
	p_err("Could not find '%s' for '%s'", val->name, func->name);
	return -ENOENT;
}

struct btf *get_btf(const char *name)
{
	char module_btf[MAX_STR];
	struct btf *btf;

	p_debug("getting BTF for %s", name ? name : "vmlinux");

	if (!name || strlen(name) == 0)
		btf = libbpf_find_kernel_btf();
	else {
		snprintf(module_btf, sizeof(module_btf),
			 "/sys/kernel/btf/%s", name);
		btf = btf__parse_split(module_btf, vmlinux_btf);
	}
	if (libbpf_get_error(btf)) {
		p_err("No BTF for '%s', cannot determine type info: %s",
		       strerror(libbpf_get_error(btf)));
		return NULL;
	}
	return btf;
}

void copy_without_spaces(char *target, char *src)
{
	for (; *src != '\0'; src++)
		if (!isspace(*src))
			*(target++) = *src;
	*target = '\0';
}

char *type_id_to_str(struct btf *btf, __s32 type_id, char *str)
{
	const struct btf_type *type;
	const char *name = "";
	char *suffix = " ";
	char *prefix = "";
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

char *value_to_str(struct btf *btf, struct value *val, char *str)
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
int get_func_ip_mod(struct func *func)
{
	char sym_type, sym_name[MAX_STR], mod_info[MAX_STR];
	unsigned long long sym_addr;
	int ret, err = 0;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		err = errno;
		p_err("failed to open /proc/kallsyms: %d\n", strerror(err));
		return err;
	}

	while (true) {
		ret = fscanf(f, "%llx %c %128s%[^\n]\n",
			     &sym_addr, &sym_type, sym_name, mod_info);
		if (ret == EOF && feof(f))
			break;
		if (ret < 3) {
			p_err("failed to read kallsyms entry: %d\n", ret);
			err = -EINVAL;
			break;
		}
		if (strcmp(func->name, sym_name) != 0)
			continue;
		func->ip = sym_addr;
		func->mod[0] = '\0';
		/* get module name from [modname] */
		if (ret == 4 &&
		    sscanf(mod_info, "%*[\t ]\[%[^]]", func->mod) == 1)
			p_debug("Module symbol '%llx' from %s'",
				func->ip, func->mod);
		p_debug("%s =  <ip %llx, mod %s>", func->name, func->ip,
			strlen(func->mod) > 0 ? func->mod : "vmlinux");
		break;
	}
	fclose(f);
	return err;
}

#define VALID_NAME	"%[A-Za-z0-9\\-_]"
#define ARGDATA		"%[^)]"

int parse_trace(char *str, struct trace *trace)
{
	struct func *func = &trace->func;
	char tracestr[MAX_STR], argdata[MAX_STR];
	char argname[MAX_STR], membername[MAX_STR];
	__u8 i, nr_predicates = 0, nr_entry = 0, nr_return = 0;
	char *arg, *saveptr;
	int ret;

	copy_without_spaces(tracestr, str);

	p_debug("Parsing trace '%s'", tracestr);

	ret = sscanf(tracestr, VALID_NAME "(" ARGDATA ")", func->name, argdata);
	switch (ret) {
	case 1:
		if (strlen(tracestr) > strlen(func->name) + 2) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		argdata[0] = '\0';
		p_debug("got func '%s'", func->name);
		break;
	case 2:
		if (strlen(tracestr) >
		    strlen(func->name) + strlen(argdata) + 2) {
			p_err("Invalid function specification '%s'", tracestr);
			usage();
		}
		p_debug("got func '%s', args '%s'", func->name, argdata);
		trace->flags |= KSNOOP_F_CUSTOM;
		break;
	default:
		usage();
	}

	/* get address of function and - if it is in a module - module name */
	ret = get_func_ip_mod(func);
	if (ret) {
		p_err("could not get address of '%s'", func->name);
		return ret;
	}

	/* get BTF associated with core kernel/module, then get info about
	 * function from that BTF.
	 */
	trace->btf = get_btf(func->mod);
	if (!trace->btf)
		return -ENOENT;
	ret = get_func_btf(trace->btf, func);
	if (ret) {
		p_debug("unexpected return value '%d' getting function", ret);
		return ret;
	}

	for (arg = strtok_r(argdata, ",", &saveptr), i = 0;
	     arg;
	     arg = strtok_r(NULL, ",", &saveptr), i++) {
		char *predicate = NULL;

		ret = sscanf(arg, VALID_NAME "->" VALID_NAME,
			     argname, membername);
		if (ret == 2) {
			if (strlen(arg) >
			    strlen(argname) + strlen(membername) + 2) {
				predicate = arg + strlen(argname) +
					    strlen(membername) + 2;
			}
			p_debug("'%s' dereferences '%s', predicate '%s'",
				argname, membername, predicate);
		} else {
			if (strlen(arg) > strlen(argname))
				predicate = arg + strlen(argname);
			p_debug("'%s' arg, predicate '%s'", argname, predicate);
			membername[0] = '\0';
		}

		if (i >= MAX_TRACES) {
			p_err("Too many arguments; up to %d are supported",
			      MAX_TRACES);
			return -EINVAL;
		}
		if (trace_to_value(trace->btf, func, argname, membername,
				   predicate, &trace->traces[i]))
			return -EINVAL;

		if (predicate)
			nr_predicates++;
		if (trace->traces[i].base_arg == KSNOOP_RETURN)
			nr_return++;
		else
			nr_entry++;

		trace->nr_traces++;
	}

	if (trace->nr_traces > 0) {
		trace->flags |= KSNOOP_F_CUSTOM;
		/* If we have one or more predicates _and_ references to
		 * entry and return values, we need to activate "stash"
		 * mode where arg traces are stored on entry and not
		 * sent until return to ensure predicates are satisfied.
		 */
		if (nr_predicates > 0 && nr_entry > 0 && nr_return > 0)
			trace->flags |= KSNOOP_F_STASH;
		p_debug("custom trace with %d args, flags 0x%x",
			trace->nr_traces, trace->flags);
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

int parse_traces(int argc, char **argv, struct trace **traces)
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
	}
	return i;
}

int cmd_info(int argc, char **argv)
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

char __indent[] = "                                                  ";

#define indent(level)	(&__indent[strlen(__indent)-level])

void print_indented(int level, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("%s", indent(level));
	vprintf(fmt, ap);
	va_end(ap);
}

void print_indented_str(int level, char *str)
{
	char *curr = str, *newline;
	char line[MAX_STR];
	bool first = true;

	while ((newline = strchr(curr, '\n')) != NULL) {
		strncpy(line, curr, newline - curr + 1);
		line[newline-curr] = '\0';
		if (first) {
			printf("%s\n", line);
			first = false;
		} else
			print_indented(level, "%s\n", line);
		curr = newline + 1;
	}
}

#define NANOSEC		1000000000

#define BASE_INDENT	48

void trace_handler(void *ctx, int cpu, void *data, __u32 size)
{
	struct trace *trace = data;
	int i, shown, level;

	if (size < (sizeof(*trace) - MAX_TRACE_BUF)) {
		fprintf(stderr, "\t/* trace buffer size '%u' < min %ld */\n",
			size, sizeof(trace) - MAX_TRACE_BUF);
		return;
	}
	/* timestamps reported in seconds/milliseconds since boot */
	printf("%20s %6u %4d %6llu.%6llu %s(\n", trace->comm, trace->pid,
	       trace->cpu, trace->time / NANOSEC,
	       (trace->time % NANOSEC)/1000, trace->func.name);
	level = BASE_INDENT;

	/* special cases; function with (void) argument or void return value. */
	for (i = 0, shown = 0; i < trace->nr_traces; i++) {
		bool entry = trace->data_flags & KSNOOP_F_ENTRY;
		bool stash = trace->flags & KSNOOP_F_STASH;

		if (!stash &&
		    ((entry && !base_arg_is_entry(trace->traces[i].base_arg)) ||
		     (!entry && base_arg_is_entry(trace->traces[i].base_arg))))
			continue;

		if (trace->traces[i].type_id == 0)
			continue;

		if (shown > 0)
			print_indented(level, ",\n\n");
		print_indented(level, "%s = ",
			       trace->traces[i].name);

		if (trace->trace_data[i].err_type_id != 0) {
			char typestr[MAX_STR];

			printf("0x%llx\n", trace->trace_data[i].raw_value);
			print_indented(level,
				       "/* Cannot show '%s' as '%s%s'.\n",
				       trace->traces[i].name,
				       type_id_to_str(trace->btf,
						      trace->traces[i].type_id,
						      typestr),
				       trace->traces[i].flags & KSNOOP_F_PTR ?
				       " *" : "");
			print_indented(level, " * Userspace/invalid ptr? */\n",
				       trace->traces[i].name);
		} else {
			if (trace->traces[i].flags & KSNOOP_F_PTR)
				printf("*");
			print_indented_str(level, trace->buf +
					   trace->trace_data[i].buf_offset);
			/* truncated? */
			if (trace->trace_data[i].buf_len == MAX_TRACE_DATA)
				print_indented(level, " ...\n");
		}
		shown++;
	}
	if (shown == 0)
		print_indented(level, "%s",
			       trace->data_flags & KSNOOP_F_ENTRY ?
			       "void" : "return;");
	printf("\n");
	print_indented(level-1, ");\n\n");
}

void lost_handler(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "\t/* lost %llu events */\n", cnt);
}

int add_traces(struct bpf_map *func_map, struct trace *traces, int nr_traces)
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

int attach_traces(struct ksnoop_bpf *skel, struct trace *traces, int nr_traces)
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

int cmd_trace(int argc, char **argv)
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
	if (!skel)
		return 1;

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
	pb = perf_buffer__new(bpf_map__fd(perf_map), 8, &pb_opts);
	if (libbpf_get_error(pb)) {
		p_err("Could not create perf buffer: %s",
		      strerror(-libbpf_get_error(pb)));
		return 1;
	}

	printf("%20s %6s %4s %13s %s\n",
	       "TASK", "PID", "CPU#", "TIMESTAMP", "FUNCTION");

	while (1) {
		ret = perf_buffer__poll(pb, 1);
		if (ret < 0 && ret != -EINTR) {
			p_err("Polling failed: %s", strerror(ret));
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

int cmd_select(int argc, char **argv)
{
	int i;

	for (i = 0; cmds[i].cmd; i++) {
		if (strncmp(*argv, cmds[i].cmd, strlen(*argv)) == 0)
			return cmds[i].func(argc - 1, argv + 1);
	}
	return cmd_trace(argc, argv);
}

int print_all_levels(enum libbpf_print_level level,
		 const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "debug",	no_argument,	NULL,	'd' },
		{ "version",	no_argument,	NULL,	'V' },
		{ "pages",	required_argument, NULL, 'p' },
		{ 0 }
	};
	int opt;

	bin_name = argv[0];

	vmlinux_btf = get_btf(NULL);
	if (libbpf_get_error(vmlinux_btf))
		return 1;

	while ((opt = getopt_long(argc, argv, "dpV", options, NULL)) >= 0) {
		switch (opt) {
		case 'd':
			libbpf_set_print(print_all_levels);
			log_level = DEBUG;
			break;
		case 'p':
			pages = atoi(optarg);
			break;
		case 'V':
			return do_version(argc, argv);
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
