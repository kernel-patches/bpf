// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "main.h"

/*
 * Decl tags added by resolve_btfids to functions in BTF_FMODRET sets. A target
 * which sleepable programs may attach to has both tags. A target which the
 * build found by analysing its code has a "bpf_fmodret_retval:" tag with the
 * values programs may return, such as "bpf_fmodret_retval:-22,-12".
 */
#define TAG_FMODRET		"bpf_fmodret"
#define TAG_FMODRET_SLEEPABLE	"bpf_fmodret_sleepable"
#define TAG_FMODRET_RETVAL	"bpf_fmodret_retval:"

#define SYS_BTF_DIR		"/sys/kernel/btf"
#define ERROR_INJECTION_LIST	"/sys/kernel/debug/error_injection/list"

struct fmodret_entry {
	__u32 btf_id;
	bool target;
	bool sleepable;
	const char *retval;
	/* More than one "bpf_fmodret_retval:" tag, which the verifier rejects */
	bool retval_dup;
};

struct fmodret_filter {
	/* Only vmlinux, or only the module with this name */
	bool vmlinux;
	const char *module;
	/* The function to show, by name or by BTF ID */
	const char *name;
	__u32 btf_id;
	unsigned int found;
	/* The BTF is the one of the running kernel */
	bool live;
};

typedef int (*btf_cb)(const char *owner, const struct btf *btf,
		      struct fmodret_filter *filter);

#define ERRNO_NAME(e) { e, #e }

/* The errors of the uapi and the kernel internal ones, which libc lacks */
static const struct {
	int value;
	const char *name;
} errno_names[] = {
	ERRNO_NAME(EPERM),
	ERRNO_NAME(ENOENT),
	ERRNO_NAME(ESRCH),
	ERRNO_NAME(EINTR),
	ERRNO_NAME(EIO),
	ERRNO_NAME(ENXIO),
	ERRNO_NAME(E2BIG),
	ERRNO_NAME(ENOEXEC),
	ERRNO_NAME(EBADF),
	ERRNO_NAME(ECHILD),
	ERRNO_NAME(EAGAIN),
	ERRNO_NAME(ENOMEM),
	ERRNO_NAME(EACCES),
	ERRNO_NAME(EFAULT),
	ERRNO_NAME(ENOTBLK),
	ERRNO_NAME(EBUSY),
	ERRNO_NAME(EEXIST),
	ERRNO_NAME(EXDEV),
	ERRNO_NAME(ENODEV),
	ERRNO_NAME(ENOTDIR),
	ERRNO_NAME(EISDIR),
	ERRNO_NAME(EINVAL),
	ERRNO_NAME(ENFILE),
	ERRNO_NAME(EMFILE),
	ERRNO_NAME(ENOTTY),
	ERRNO_NAME(ETXTBSY),
	ERRNO_NAME(EFBIG),
	ERRNO_NAME(ENOSPC),
	ERRNO_NAME(ESPIPE),
	ERRNO_NAME(EROFS),
	ERRNO_NAME(EMLINK),
	ERRNO_NAME(EPIPE),
	ERRNO_NAME(EDOM),
	ERRNO_NAME(ERANGE),
	ERRNO_NAME(EDEADLK),
#if defined(EDEADLOCK) && EDEADLOCK != EDEADLK
	ERRNO_NAME(EDEADLOCK),
#endif
	ERRNO_NAME(ENAMETOOLONG),
	ERRNO_NAME(ENOLCK),
	ERRNO_NAME(ENOSYS),
	ERRNO_NAME(ENOTEMPTY),
	ERRNO_NAME(ELOOP),
	ERRNO_NAME(ENOMSG),
	ERRNO_NAME(EIDRM),
	ERRNO_NAME(ECHRNG),
	ERRNO_NAME(EL2NSYNC),
	ERRNO_NAME(EL3HLT),
	ERRNO_NAME(EL3RST),
	ERRNO_NAME(ELNRNG),
	ERRNO_NAME(EUNATCH),
	ERRNO_NAME(ENOCSI),
	ERRNO_NAME(EL2HLT),
	ERRNO_NAME(EBADE),
	ERRNO_NAME(EBADR),
	ERRNO_NAME(EXFULL),
	ERRNO_NAME(ENOANO),
	ERRNO_NAME(EBADRQC),
	ERRNO_NAME(EBADSLT),
	ERRNO_NAME(EBFONT),
	ERRNO_NAME(ENOSTR),
	ERRNO_NAME(ENODATA),
	ERRNO_NAME(ETIME),
	ERRNO_NAME(ENOSR),
	ERRNO_NAME(ENONET),
	ERRNO_NAME(ENOPKG),
	ERRNO_NAME(EREMOTE),
	ERRNO_NAME(ENOLINK),
	ERRNO_NAME(EADV),
	ERRNO_NAME(ESRMNT),
	ERRNO_NAME(ECOMM),
	ERRNO_NAME(EPROTO),
	ERRNO_NAME(EMULTIHOP),
	ERRNO_NAME(EDOTDOT),
	ERRNO_NAME(EBADMSG),
	ERRNO_NAME(EOVERFLOW),
	ERRNO_NAME(ENOTUNIQ),
	ERRNO_NAME(EBADFD),
	ERRNO_NAME(EREMCHG),
	ERRNO_NAME(ELIBACC),
	ERRNO_NAME(ELIBBAD),
	ERRNO_NAME(ELIBSCN),
	ERRNO_NAME(ELIBMAX),
	ERRNO_NAME(ELIBEXEC),
	ERRNO_NAME(EILSEQ),
	ERRNO_NAME(ERESTART),
	ERRNO_NAME(ESTRPIPE),
	ERRNO_NAME(EUSERS),
	ERRNO_NAME(ENOTSOCK),
	ERRNO_NAME(EDESTADDRREQ),
	ERRNO_NAME(EMSGSIZE),
	ERRNO_NAME(EPROTOTYPE),
	ERRNO_NAME(ENOPROTOOPT),
	ERRNO_NAME(EPROTONOSUPPORT),
	ERRNO_NAME(ESOCKTNOSUPPORT),
	ERRNO_NAME(EOPNOTSUPP),
	ERRNO_NAME(EPFNOSUPPORT),
	ERRNO_NAME(EAFNOSUPPORT),
	ERRNO_NAME(EADDRINUSE),
	ERRNO_NAME(EADDRNOTAVAIL),
	ERRNO_NAME(ENETDOWN),
	ERRNO_NAME(ENETUNREACH),
	ERRNO_NAME(ENETRESET),
	ERRNO_NAME(ECONNABORTED),
	ERRNO_NAME(ECONNRESET),
	ERRNO_NAME(ENOBUFS),
	ERRNO_NAME(EISCONN),
	ERRNO_NAME(ENOTCONN),
	ERRNO_NAME(ESHUTDOWN),
	ERRNO_NAME(ETOOMANYREFS),
	ERRNO_NAME(ETIMEDOUT),
	ERRNO_NAME(ECONNREFUSED),
	ERRNO_NAME(EHOSTDOWN),
	ERRNO_NAME(EHOSTUNREACH),
	ERRNO_NAME(EALREADY),
	ERRNO_NAME(EINPROGRESS),
	ERRNO_NAME(ESTALE),
	ERRNO_NAME(EUCLEAN),
	ERRNO_NAME(ENOTNAM),
	ERRNO_NAME(ENAVAIL),
	ERRNO_NAME(EISNAM),
	ERRNO_NAME(EREMOTEIO),
	ERRNO_NAME(EDQUOT),
	ERRNO_NAME(ENOMEDIUM),
	ERRNO_NAME(EMEDIUMTYPE),
	ERRNO_NAME(ECANCELED),
	ERRNO_NAME(ENOKEY),
	ERRNO_NAME(EKEYEXPIRED),
	ERRNO_NAME(EKEYREVOKED),
	ERRNO_NAME(EKEYREJECTED),
	ERRNO_NAME(EOWNERDEAD),
	ERRNO_NAME(ENOTRECOVERABLE),
	ERRNO_NAME(ERFKILL),
	ERRNO_NAME(EHWPOISON),
#ifdef EFTYPE
	ERRNO_NAME(EFTYPE),
#endif
	{ 512, "ERESTARTSYS" },
	{ 513, "ERESTARTNOINTR" },
	{ 514, "ERESTARTNOHAND" },
	{ 515, "ENOIOCTLCMD" },
	{ 516, "ERESTART_RESTARTBLOCK" },
	{ 517, "EPROBE_DEFER" },
	{ 518, "EOPENSTALE" },
	{ 519, "ENOPARAM" },
	{ 521, "EBADHANDLE" },
	{ 522, "ENOTSYNC" },
	{ 523, "EBADCOOKIE" },
	{ 524, "ENOTSUPP" },
	{ 525, "ETOOSMALL" },
	{ 526, "ESERVERFAULT" },
	{ 527, "EBADTYPE" },
	{ 528, "EJUKEBOX" },
	{ 529, "EIOCBQUEUED" },
	{ 530, "ERECALLCONFLICT" },
	{ 531, "ENOGRACE" },
};

static const char *errno_name(long long value)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(errno_names); i++)
		if (-(long long)errno_names[i].value == value)
			return errno_names[i].name;
	return NULL;
}

static int cmp_entry(const void *a, const void *b)
{
	const struct fmodret_entry *x = a, *y = b;

	return (x->btf_id > y->btf_id) - (x->btf_id < y->btf_id);
}

/* The first type ID which belongs to BTF and not to its base */
static __u32 first_own_type(const struct btf *btf)
{
	const struct btf *base = btf__base_btf(btf);

	return base ? btf__type_cnt(base) : 1;
}

/*
 * Return the function which T tags with decl tag NAME, or 0. A NAME which ends
 * with ':' matches the tags which start with it.
 */
static __u32 tag_func(const struct btf *btf, const struct btf_type *t, const char *name)
{
	size_t len = strlen(name);
	const char *tag;

	if (!btf_is_decl_tag(t) || btf_decl_tag(t)->component_idx != -1)
		return 0;
	tag = btf__name_by_offset(btf, t->name_off);
	if (strncmp(tag, name, len) || (name[len - 1] != ':' && tag[len]))
		return 0;
	if (!btf_is_func(btf__type_by_id(btf, t->type)))
		return 0;
	return t->type;
}

/* Return the fmod_ret targets of BTF, sorted by BTF ID */
static int collect_targets(const struct btf *btf, struct fmodret_entry **targets,
			   size_t *target_cnt)
{
	__u32 id, func_id, start_id = first_own_type(btf);
	__u32 nr_types = btf__type_cnt(btf);
	struct fmodret_entry *entries = NULL, *entry, *tmp;
	size_t cnt = 0, capacity = 0;

	for (id = start_id; id < nr_types; id++) {
		func_id = tag_func(btf, btf__type_by_id(btf, id), TAG_FMODRET);
		if (!func_id)
			continue;

		if (cnt == capacity) {
			capacity = capacity ? 2 * capacity : 64;
			tmp = realloc(entries, capacity * sizeof(*entries));
			if (!tmp) {
				free(entries);
				return -ENOMEM;
			}
			entries = tmp;
		}
		entries[cnt].btf_id = func_id;
		entries[cnt].target = true;
		entries[cnt].sleepable = false;
		entries[cnt].retval = NULL;
		cnt++;
	}
	if (cnt)
		qsort(entries, cnt, sizeof(*entries), cmp_entry);

	/* The other tags mark functions which are already targets */
	for (id = start_id; cnt && id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		struct fmodret_entry key = {};

		key.btf_id = tag_func(btf, t, TAG_FMODRET_SLEEPABLE);
		if (key.btf_id) {
			entry = bsearch(&key, entries, cnt, sizeof(*entries), cmp_entry);
			if (entry)
				entry->sleepable = true;
			continue;
		}
		key.btf_id = tag_func(btf, t, TAG_FMODRET_RETVAL);
		if (key.btf_id) {
			entry = bsearch(&key, entries, cnt, sizeof(*entries), cmp_entry);
			if (entry)
				entry->retval = btf__name_by_offset(btf, t->name_off) +
						strlen(TAG_FMODRET_RETVAL);
		}
	}

	*targets = entries;
	*target_cnt = cnt;
	return 0;
}

/* Fill ENTRY from the decl tags of function FUNC_ID */
static void func_entry(const struct btf *btf, __u32 func_id, struct fmodret_entry *entry)
{
	__u32 id, nr_types = btf__type_cnt(btf);

	memset(entry, 0, sizeof(*entry));
	entry->btf_id = func_id;
	for (id = first_own_type(btf); id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (tag_func(btf, t, TAG_FMODRET) == func_id)
			entry->target = true;
		else if (tag_func(btf, t, TAG_FMODRET_SLEEPABLE) == func_id)
			entry->sleepable = true;
		else if (tag_func(btf, t, TAG_FMODRET_RETVAL) == func_id) {
			entry->retval_dup = entry->retval;
			entry->retval = btf__name_by_offset(btf, t->name_off) +
					strlen(TAG_FMODRET_RETVAL);
		}
	}
}

static void list_target(const char *owner, const struct btf *btf,
			const struct fmodret_entry *entry)
{
	const struct btf_type *t = btf__type_by_id(btf, entry->btf_id);
	const char *name = btf__name_by_offset(btf, t->name_off);

	if (json_output) {
		jsonw_start_object(json_wtr);
		jsonw_uint_field(json_wtr, "btf_id", entry->btf_id);
		jsonw_string_field(json_wtr, "name", name);
		jsonw_string_field(json_wtr, "owner", owner);
		jsonw_bool_field(json_wtr, "sleepable", entry->sleepable);
		jsonw_end_object(json_wtr);
	} else {
		printf("%u  %s (%s)%s\n", entry->btf_id, name, owner,
		       entry->sleepable ? " sleepable" : "");
	}
}

static int list_btf(const char *owner, const struct btf *btf,
		    struct fmodret_filter *filter)
{
	struct fmodret_entry *targets = NULL;
	size_t cnt = 0, i;
	int err;

	err = collect_targets(btf, &targets, &cnt);
	if (err) {
		p_err("failed to collect fmod_ret targets of %s: %s", owner,
		      strerror(-err));
		return err;
	}
	for (i = 0; i < cnt; i++)
		list_target(owner, btf, &targets[i]);
	free(targets);
	return 0;
}

struct error_injection {
	char *name;
	char *module;
	char *type;
};

static struct error_injection *error_injections;
static size_t error_injection_cnt;

/*
 * Read the error injection list of the running kernel. Its lines are
 * "FUNC\tTYPE" and "FUNC [MODULE]\tTYPE". Without debugfs the list is empty.
 */
static void read_error_injection_list(void)
{
	struct error_injection *tmp;
	char *line = NULL;
	size_t len = 0;
	FILE *f;

	f = fopen(ERROR_INJECTION_LIST, "r");
	if (!f)
		return;
	while (getline(&line, &len, f) > 0) {
		char *name, *module = NULL, *type, *save;

		/* "NAME [MODULE]\tTYPE" or "NAME\tTYPE" */
		name = strtok_r(line, " \t\n", &save);
		type = strtok_r(NULL, " \t\n", &save);
		if (type && type[0] == '[') {
			module = type + 1;
			module[strcspn(module, "]")] = '\0';
			type = strtok_r(NULL, " \t\n", &save);
		}
		if (!name || !type)
			continue;
		tmp = realloc(error_injections,
			      (error_injection_cnt + 1) * sizeof(*error_injections));
		if (!tmp)
			break;
		error_injections = tmp;
		tmp = &error_injections[error_injection_cnt];
		tmp->name = strdup(name);
		tmp->module = strdup(module ?: "");
		tmp->type = strdup(type);
		if (!tmp->name || !tmp->module || !tmp->type) {
			free(tmp->name);
			free(tmp->module);
			free(tmp->type);
			break;
		}
		error_injection_cnt++;
	}
	free(line);
	fclose(f);
}

static void free_error_injection_list(void)
{
	size_t i;

	for (i = 0; i < error_injection_cnt; i++) {
		free(error_injections[i].name);
		free(error_injections[i].module);
		free(error_injections[i].type);
	}
	free(error_injections);
	error_injections = NULL;
	error_injection_cnt = 0;
}

/* Return the error injection type of function NAME of OWNER, or NULL */
static const char *error_injection_type(const char *name, const char *owner)
{
	const char *module = strcmp(owner, "vmlinux") ? owner : "";
	size_t i;

	for (i = 0; i < error_injection_cnt; i++)
		if (!strcmp(error_injections[i].name, name) &&
		    !strcmp(error_injections[i].module, module))
			return error_injections[i].type;
	return NULL;
}

static void __printf(2, 0) prototype_printf(void *ctx, const char *fmt, va_list args)
{
	vfprintf(ctx, fmt, args);
}

/* Return the declaration of function FUNC_ID, or NULL */
static char *func_prototype(const struct btf *btf, __u32 func_id)
{
	const struct btf_type *t = btf__type_by_id(btf, func_id);
	LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts,
		.field_name = btf__name_by_offset(btf, t->name_off),
	);
	struct btf_dump *d;
	char *buf = NULL;
	size_t size = 0;
	FILE *f;
	int err;

	f = open_memstream(&buf, &size);
	if (!f)
		return NULL;
	d = btf_dump__new(btf, prototype_printf, f, NULL);
	err = libbpf_get_error(d);
	if (!err) {
		err = btf_dump__emit_type_decl(d, t->type, &opts);
		btf_dump__free(d);
	}
	fclose(f);
	if (err) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* Show 0 and the values of a "bpf_fmodret_retval:" tag as a JSON array */
static void show_retval_json(const char *retval)
{
	const char *p = retval;
	char *end;

	jsonw_name(json_wtr, "retval");
	jsonw_start_array(json_wtr);
	jsonw_int(json_wtr, 0);
	while (*p) {
		long long value;

		errno = 0;
		value = strtoll(p, &end, 10);
		if (end == p || errno)
			break;
		jsonw_int(json_wtr, value);
		p = *end == ',' ? end + 1 : end;
	}
	jsonw_end_array(json_wtr);
}

/*
 * Check the "bpf_fmodret_retval:" tag of FUNC_ID as the verifier does: negative
 * decimal numbers separated by commas, which the integer or enum of 4 or 8 bytes
 * that the function returns can hold. Return why it is invalid, or NULL.
 */
static const char *retval_invalid(const struct btf *btf, __u32 func_id,
				  const char *retval)
{
	const struct btf_type *t = btf__type_by_id(btf, func_id);
	const char *p = retval;
	int ret_id;
	char *end;

	t = btf__type_by_id(btf, t->type);
	ret_id = t ? btf__resolve_type(btf, t->type) : -EINVAL;
	t = ret_id > 0 ? btf__type_by_id(btf, ret_id) : NULL;
	if (!t || !(btf_is_int(t) || btf_is_any_enum(t)) || (t->size != 4 && t->size != 8))
		return "the function does not return an integer of 4 or 8 bytes";
	for (;;) {
		long long value;

		if (*p != '-')
			return "malformed tag";
		errno = 0;
		value = strtoll(p, &end, 10);
		if (end == p || errno || value >= 0)
			return "malformed tag";
		if (t->size == 4 && value < INT_MIN)
			return "a value does not fit the return type";
		if (!*end)
			return NULL;
		if (*end != ',')
			return "malformed tag";
		p = end + 1;
	}
}

/* Show the values of a "bpf_fmodret_retval:" tag with the names of errors */
static void show_retval_plain(const char *retval)
{
	const char *p = retval, *name;
	char *end;

	printf("\tretval: 0");
	while (*p) {
		long long value;

		errno = 0;
		value = strtoll(p, &end, 10);
		if (end == p || errno)
			break;
		printf(", %lld", value);
		name = errno_name(value);
		if (name)
			printf(" (%s)", name);
		p = *end == ',' ? end + 1 : end;
	}
	printf("\n");
}

static int show_function(const char *owner, const struct btf *btf,
			 const struct fmodret_entry *entry,
			 struct fmodret_filter *filter)
{
	const struct btf_type *t = btf__type_by_id(btf, entry->btf_id);
	const char *name = btf__name_by_offset(btf, t->name_off);
	const char *injection = NULL, *invalid = NULL;
	char *prototype;

	/* The verifier rejects programs on a function with an invalid tag */
	if (entry->target && entry->retval_dup)
		invalid = "more than one tag";
	else if (entry->target && entry->retval)
		invalid = retval_invalid(btf, entry->btf_id, entry->retval);
	prototype = func_prototype(btf, entry->btf_id);
	if (!prototype) {
		p_err("failed to print the prototype of %s", name);
		return -EINVAL;
	}
	if (filter->live)
		injection = error_injection_type(name, owner);

	if (json_output) {
		jsonw_start_object(json_wtr);
		jsonw_uint_field(json_wtr, "btf_id", entry->btf_id);
		jsonw_string_field(json_wtr, "name", name);
		jsonw_string_field(json_wtr, "owner", owner);
		jsonw_string_field(json_wtr, "prototype", prototype);
		jsonw_string_field(json_wtr, "target", !entry->target ? "none" :
				   entry->retval ? "found" : "declared");
		jsonw_bool_field(json_wtr, "sleepable", entry->target && entry->sleepable);
		if (invalid)
			jsonw_string_field(json_wtr, "retval_error", invalid);
		else if (entry->target && entry->retval)
			show_retval_json(entry->retval);
		if (injection)
			jsonw_string_field(json_wtr, "error_injection", injection);
		jsonw_end_object(json_wtr);
	} else {
		printf("%u  %s (%s)\n", entry->btf_id, name, owner);
		printf("\t%s\n", prototype);
		if (entry->target) {
			printf("\ttarget: %s\n", entry->retval ? "found by the kernel build" :
			       "declared");
			printf("\tsleepable: %s\n", entry->sleepable ? "yes" : "no");
			if (invalid)
				printf("\tretval: invalid, %s\n", invalid);
			else if (entry->retval)
				show_retval_plain(entry->retval);
			else
				printf("\tretval: any\n");
		} else {
			printf("\ttarget: not tagged, the verifier may accept it by other rules\n");
		}
		if (injection)
			printf("\terror injection: %s\n", injection);
	}
	free(prototype);
	filter->found++;
	return 0;
}

static int show_btf(const char *owner, const struct btf *btf,
		    struct fmodret_filter *filter)
{
	__u32 id, nr_types = btf__type_cnt(btf);
	struct fmodret_entry entry;
	int err;

	if (filter->btf_id) {
		if (filter->btf_id < first_own_type(btf) || filter->btf_id >= nr_types ||
		    !btf_is_func(btf__type_by_id(btf, filter->btf_id)))
			return 0;
		func_entry(btf, filter->btf_id, &entry);
		return show_function(owner, btf, &entry, filter);
	}

	for (id = first_own_type(btf); id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!btf_is_func(t) ||
		    strcmp(btf__name_by_offset(btf, t->name_off), filter->name))
			continue;
		func_entry(btf, id, &entry);
		err = show_function(owner, btf, &entry, filter);
		if (err)
			return err;
	}
	return 0;
}

static int filter_module(const struct dirent *entry)
{
	size_t len = strlen(entry->d_name);

	/* Skip ".", "..", vmlinux and the ".inline" companions of modules */
	return entry->d_name[0] != '.' && strcmp(entry->d_name, "vmlinux") &&
	       !(len > 7 && !strcmp(entry->d_name + len - 7, ".inline"));
}

static int walk_modules(struct btf *vmlinux, struct fmodret_filter *filter, btf_cb cb)
{
	struct dirent **modules = NULL;
	int i, nr_modules, err = 0;

	if (filter->module) {
		struct btf *btf;

		btf = btf__load_module_btf(filter->module, vmlinux);
		err = libbpf_get_error(btf);
		if (err) {
			p_err("failed to load BTF of module %s: %s", filter->module,
			      strerror(-err));
			return err;
		}
		err = cb(filter->module, btf, filter);
		btf__free(btf);
		return err;
	}

	nr_modules = scandir(SYS_BTF_DIR, &modules, filter_module, alphasort);
	if (nr_modules < 0) {
		/* There is no module directory without module BTF, which is fine */
		if (errno == ENOENT)
			return 0;
		err = -errno;
		p_err("failed to read %s: %s", SYS_BTF_DIR, strerror(errno));
		return err;
	}
	for (i = 0; i < nr_modules; i++) {
		const char *name = modules[i]->d_name;
		struct btf *btf;

		btf = btf__load_module_btf(name, vmlinux);
		err = libbpf_get_error(btf);
		if (err == -ENOENT) {
			/* The module was unloaded meanwhile */
			err = 0;
			continue;
		}
		if (err) {
			p_err("failed to load BTF of module %s: %s", name, strerror(-err));
			break;
		}
		err = cb(name, btf, filter);
		btf__free(btf);
		if (err)
			break;
	}
	for (i = 0; i < nr_modules; i++)
		free(modules[i]);
	free(modules);
	return err;
}

static int walk_live_btf(struct fmodret_filter *filter, btf_cb cb)
{
	struct btf *vmlinux;
	int err = 0;

	vmlinux = btf__load_vmlinux_btf();
	err = libbpf_get_error(vmlinux);
	if (err) {
		p_err("failed to load vmlinux BTF: %s", strerror(-err));
		return err;
	}
	if (!filter->module)
		err = cb("vmlinux", vmlinux, filter);
	if (!err && !filter->vmlinux)
		err = walk_modules(vmlinux, filter, cb);
	btf__free(vmlinux);
	return err;
}

static int walk_file_btf(const char *path, struct fmodret_filter *filter, btf_cb cb)
{
	struct btf *btf;
	int err;

	btf = base_btf ? btf__parse_split(path, base_btf) : btf__parse(path, NULL);
	err = libbpf_get_error(btf);
	if (err) {
		p_err("failed to parse BTF from %s: %s", path, strerror(-err));
		return err;
	}
	err = cb(path, btf, filter);
	btf__free(btf);
	return err;
}

/* Parse the optional OBJECT := { file FILE | vmlinux | module NAME } */
static int parse_object(int argc, char **argv, const char **path,
			struct fmodret_filter *filter)
{
	if (!argc)
		return 0;
	if (is_prefix(*argv, "vmlinux")) {
		filter->vmlinux = true;
		NEXT_ARG();
	} else if (is_prefix(*argv, "file")) {
		NEXT_ARG();
		if (!REQ_ARGS(1))
			return -1;
		*path = GET_ARG();
	} else if (is_prefix(*argv, "module")) {
		NEXT_ARG();
		if (!REQ_ARGS(1))
			return -1;
		filter->module = GET_ARG();
	}
	if (argc)
		return BAD_ARG();
	return 0;
}

static int walk_btf(const char *path, struct fmodret_filter *filter, btf_cb cb)
{
	return path ? walk_file_btf(path, filter, cb) : walk_live_btf(filter, cb);
}

static int do_list(int argc, char **argv)
{
	struct fmodret_filter filter = {};
	const char *path = NULL;
	int err;

	if (parse_object(argc, argv, &path, &filter))
		return -1;

	if (json_output)
		jsonw_start_array(json_wtr);
	err = walk_btf(path, &filter, list_btf);
	if (json_output)
		jsonw_end_array(json_wtr);
	return err;
}

static int do_show(int argc, char **argv)
{
	struct fmodret_filter filter = {};
	const char *path = NULL;
	unsigned long id;
	char *endptr;
	int err;

	if (!REQ_ARGS(2))
		return -1;
	if (is_prefix(*argv, "name")) {
		NEXT_ARG();
		filter.name = GET_ARG();
	} else if (is_prefix(*argv, "id")) {
		NEXT_ARG();
		errno = 0;
		id = strtoul(*argv, &endptr, 0);
		if (errno || *endptr || !id || id > UINT_MAX || **argv == '-') {
			p_err("can't parse %s as BTF ID", *argv);
			return -1;
		}
		filter.btf_id = id;
		NEXT_ARG();
	} else {
		p_err("expected 'name' or 'id', got: '%s'", *argv);
		return -1;
	}
	if (parse_object(argc, argv, &path, &filter))
		return -1;
	/* The BTF IDs of different modules overlap */
	if (filter.btf_id && !path && !filter.module)
		filter.vmlinux = true;

	filter.live = !path;
	if (filter.live)
		read_error_injection_list();
	/* A BTF ID gives one function, a name an array of them */
	if (json_output && !filter.btf_id)
		jsonw_start_array(json_wtr);
	err = walk_btf(path, &filter, show_btf);
	if (!err && !filter.found) {
		if (filter.name)
			p_err("no function named %s", filter.name);
		else
			p_err("no function with BTF ID %u", filter.btf_id);
		err = -ENOENT;
	}
	if (json_output && !filter.btf_id)
		jsonw_end_array(json_wtr);
	free_error_injection_list();
	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s list [OBJECT]\n"
		"       %1$s %2$s show FUNC [OBJECT]\n"
		"       %1$s %2$s help\n"
		"\n"
		"       FUNC := { name NAME | id BTF_ID }\n"
		"       OBJECT := { file FILE | vmlinux | module NAME }\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-B|--base-btf} FILE }\n"
		"\n",
		bin_name, "fmodret");
	return 0;
}

static const struct cmd cmds[] = {
	{ "list",	do_list },
	{ "show",	do_show },
	{ "help",	do_help },
	{ 0 }
};

int do_fmodret(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
