// SPDX-License-Identifier: GPL-2.0
/*
 * BPF monitor support: allows rv to control BPF monitors.
 *
 * Copyright (C) 2026 Red Hat Inc, Gabriele Monaco <gmonaco@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>
#include <inttypes.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include <bpf_monitor.h>
#include <utils.h>
#include <rv.h>

static char bpf_base_paths[][MAX_PATH] = {
	".",
	"/etc/rv",
	"/usr/local/share/rv",
	"/usr/share/rv",
	"", /* Marker */
};

/* Path used for development, searched first */
#define DEVEL_PATH 0

#define MAX_ENUMS 64
#define MAX_LINKS 16
#define PROG_ENABLE_MON "enable_monitor"
#define RV_TRACE_STRUCT "rv_trace_entry"
#define RV_TRACE_TYPE_ENUM "rv_trace_type"

enum trace_type_id {
	TRACE_TYPE_ERROR,
	TRACE_TYPE_EVENT,
	TRACE_TYPE_MAX,
};

static const char *const trace_type_names[] = {
	[TRACE_TYPE_ERROR] = "RV_TRACE_ERROR",
	[TRACE_TYPE_EVENT] = "RV_TRACE_EVENT",
};

enum field_id {
	FIELD_EVENT_TYPE,
	FIELD_ID,
	FIELD_CPU,
	FIELD_PID,
	FIELD_COMM,
	FIELD_IS_FINAL,
	FIELD_CURR_STATE,
	FIELD_EVENT,
	FIELD_NEXT_STATE,
	FIELD_MAX,
};

static const char *const field_names[] = {
	[FIELD_EVENT_TYPE] = "event_type",
	[FIELD_ID] = "id",
	[FIELD_CPU] = "cpu",
	[FIELD_PID] = "pid",
	[FIELD_COMM] = "comm",
	[FIELD_IS_FINAL] = "is_final",
	[FIELD_CURR_STATE] = "curr_state",
	[FIELD_EVENT] = "event",
	[FIELD_NEXT_STATE] = "next_state",
};

struct field {
	size_t offset;
	size_t size;
};

struct bpf_monitor_ctx {
	char monitor_name[MAX_DA_NAME_LEN];
	char state_names[MAX_ENUMS][MAX_DA_NAME_LEN];
	char event_names[MAX_ENUMS][MAX_DA_NAME_LEN];
	int num_states;
	int num_events;
	struct field field_metadata[FIELD_MAX];
	int trace_types[TRACE_TYPE_MAX];
};

/*
 * bpf_read_enable - reads monitor's enable status
 *
 * Iterate through all BPF maps in the system, if the rv_mon_NAME map is
 * loaded, the monitor is enabled.
 * Since map names have limited size and may get truncated, check that also the
 * corresponding BTF matches.
 */
static int bpf_read_enable(const char *monitor_name)
{
	char ringbuf_name[2 * MAX_DA_NAME_LEN];
	uint32_t id = 0;

	snprintf(ringbuf_name, sizeof(ringbuf_name),
		 "rv_mon_%s", monitor_name);

	while (bpf_map_get_next_id(id, &id) == 0) {
		struct bpf_map_info info = { 0 };
		uint32_t info_len = sizeof(info);
		struct btf *btf;
		int type_id;
		int fd = bpf_map_get_fd_by_id(id);

		if (fd < 0)
			continue;

		if (bpf_map_get_info_by_fd(fd, &info, &info_len) != 0) {
			close(fd);
			continue;
		}
		close(fd);

		if (strncmp(info.name, ringbuf_name, BPF_OBJ_NAME_LEN - 1) != 0)
			continue;

		if (!info.btf_id)
			continue;
		btf = btf__load_from_kernel_by_id(info.btf_id);
		if (!btf)
			continue;

		type_id = btf__find_by_name_kind(btf, ringbuf_name, BTF_KIND_VAR);
		btf__free(btf);
		if (type_id > 0)
			return 1;
	}

	return 0;
}

/*
 * bpf_read_desc - read monitors' description
 *
 * Return the provided string containing the monitor's description, NULL
 * otherwise.
 */
static char *bpf_read_desc(char *desc, struct bpf_object *obj, const char *monitor_name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, ".rodata.description");
	const char *desc_data;
	size_t desc_size;

	if (!map) {
		debug_msg("bpf: cannot find description for %s\n",
			  monitor_name);
		return NULL;
	}
	desc_data = bpf_map__initial_value(map, &desc_size);
	if (!desc_data || desc_size == 0) {
		debug_msg("bpf: empty description for %s\n", monitor_name);
		*desc = 0;
		return desc;
	}

	if (desc_size >= MAX_DESCRIPTION)
		desc_size = MAX_DESCRIPTION - 1;
	strncpy(desc, desc_data, desc_size);
	desc[desc_size] = '\0';

	return desc;
}

/*
 * bpf_fill_base_paths - fill the path for development builds
 *
 * RV searches for BPF monitors on absolute paths on the system as well
 * as in the same directory of the rv binary. This is useful when running
 * rv from the kernel tree. This function resolves the right location.
 */
static void bpf_fill_base_paths(void)
{
	char tmp_path[MAX_PATH], *dir;
	ssize_t len;

	len = readlink("/proc/self/exe", tmp_path, MAX_PATH);
	if (len > 0 && len != MAX_PATH) {
		tmp_path[len] = '\0';
		dir = dirname(tmp_path);
		snprintf(bpf_base_paths[DEVEL_PATH], MAX_PATH, "%s", dir);
	}
}

static void bpf_object_iterate_path(const char *base_path, const char *subdir,
				    void (*action)(const char *name, struct bpf_object *obj))
{
	char path[MAX_PATH];
	struct dirent *entry;
	DIR *dir;
	char *ext;

	snprintf(path, sizeof(path), "%s/%s", base_path, subdir);
	dir = opendir(path);
	if (!dir) {
		debug_msg("bpf: error opening directory: %s\n", path);
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		size_t size;
		struct bpf_object *obj;
		char name[MAX_DA_NAME_LEN], obj_path[MAX_PATH];

		if (entry->d_name[0] == '.')
			continue;

		ext = strrchr(entry->d_name, '.');
		if (!ext || strcmp(ext, ".o") != 0)
			continue;

		size = snprintf(obj_path, sizeof(obj_path), "%s/%s", path,
				entry->d_name);
		obj = bpf_object__open_file(obj_path, NULL);
		if (!obj || size > MAX_PATH) {
			err_msg("bpf: error opening object file %s: %s\n",
				obj_path, strerror(errno));
			continue;
		}

		strncpy(name, entry->d_name, sizeof(name));
		ext = strrchr(name, '.');
		if (ext)
			*ext = '\0';

		action(name, obj);

		bpf_object__close(obj);
	}

	closedir(dir);
}

static void list_monitor_action(const char *name, struct bpf_object *obj)
{
	char desc[MAX_DESCRIPTION];

	if (!bpf_read_desc(desc, obj, name)) {
		err_msg("bpf: monitor %s does not have desc map, bug?\n", name);
		return;
	}

	printf("%-*s %s %s\n", MAX_DA_NAME_LEN, name,
	       desc, bpf_read_enable(name) ? "[ON]" : "[OFF]");
}

/*
 * list_monitors_from_path - list monitors from a specific base path
 */
static void list_monitors_from_path(const char *base_path)
{
	bpf_object_iterate_path(base_path, "bpf_monitors", list_monitor_action);
}

/*
 * bpf_list_monitors - list available BPF monitors from all sources
 *
 * @container: BPF monitors are not nested, skip listing.
 *
 * Returns 0 on success
 */
int bpf_list_monitors(char *container)
{
	if (container)
		return 0;
	bpf_fill_base_paths();
	for (int i = 0; bpf_base_paths[i][0]; i++)
		list_monitors_from_path(bpf_base_paths[i]);

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !config.debug)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * Helper functions for state/event name lookup
 */
static const char *get_state_name(struct bpf_monitor_ctx *ctx, uint32_t state)
{
	if (state < ctx->num_states)
		return ctx->state_names[state];

	return "<invalid>";
}

static const char *get_event_name(struct bpf_monitor_ctx *ctx, uint32_t event)
{
	if (event < ctx->num_events)
		return ctx->event_names[event];

	return "<invalid>";
}

/*
 * extract_field_metadata - extract field metadata from BTF for efficient parsing
 *
 * Introspect the rv_trace_entry structure via BTF and store field offsets and
 * sizes for direct memory access during event processing.
 * This allows for parsing known fields without having to stick to a particular
 * memory layout in future releases.
 *
 * Returns 0 on success, -1 on error
 */
static int extract_field_metadata(const struct btf *btf, struct bpf_monitor_ctx *ctx)
{
	const struct btf_type *trace_type;
	const struct btf_member *members;
	int type_id, vlen;

	type_id = btf__find_by_name_kind(btf, RV_TRACE_STRUCT, BTF_KIND_STRUCT);
	if (type_id <= 0) {
		debug_msg("bpf: could not find struct '%s' in BTF\n", RV_TRACE_STRUCT);
		return -1;
	}

	trace_type = btf__type_by_id(btf, type_id);
	if (!trace_type) {
		debug_msg("bpf: could not get type for '%s'\n", RV_TRACE_STRUCT);
		return -1;
	}

	members = btf_members(trace_type);
	vlen = btf_vlen(trace_type);

	for (int i = 0; i < vlen; i++) {
		const char *name = btf__name_by_offset(btf, members[i].name_off);
		size_t offset = btf_member_bit_offset(trace_type, i) / 8;
		size_t size = btf__resolve_size(btf, members[i].type);

		if (!name || (ssize_t)size < 0)
			continue;

		debug_msg("bpf: field '%s' at offset %zu, size %lld\n", name,
			  offset, (long long)size);

		for (int j = 0; j < FIELD_MAX; j++) {
			if (strcmp(name, field_names[j]) == 0) {
				ctx->field_metadata[j].offset = offset;
				ctx->field_metadata[j].size = size;
				if (j == FIELD_ID)
					config.has_id = true;
				break;
			}
		}
	}

	return 0;
}

/*
 * extract_trace_type_metadata - extract trace type enum values from BTF
 *
 * Introspect the rv_trace_type enum via BTF and store enum values for
 * event type dispatch and configuration.
 *
 * Returns 0 on success, -1 on error
 */
static int extract_trace_type_metadata(const struct btf *btf, struct bpf_monitor_ctx *ctx)
{
	const struct btf_type *enum_type;
	const struct btf_enum *enums;
	int type_id, vlen, filled = 0;

	for (int i = 0; i < TRACE_TYPE_MAX; i++)
		ctx->trace_types[i] = -1;

	type_id = btf__find_by_name_kind(btf, RV_TRACE_TYPE_ENUM, BTF_KIND_ENUM);
	if (type_id <= 0) {
		debug_msg("bpf: could not find enum '%s' in BTF\n", RV_TRACE_TYPE_ENUM);
		return -1;
	}

	enum_type = btf__type_by_id(btf, type_id);
	if (!enum_type) {
		debug_msg("bpf: could not get type for '%s'\n", RV_TRACE_TYPE_ENUM);
		return -1;
	}

	enums = btf_enum(enum_type);
	vlen = btf_vlen(enum_type);

	for (int i = 0; i < vlen; i++) {
		const char *name = btf__name_by_offset(btf, enums[i].name_off);

		if (!name)
			continue;

		for (int j = 0; j < TRACE_TYPE_MAX; j++) {
			if (strcmp(name, trace_type_names[j]) == 0) {
				ctx->trace_types[j] = enums[i].val;
				++filled;
				break;
			}
		}
	}

	if (filled < TRACE_TYPE_MAX) {
		debug_msg("bpf: could not find all trace types in BTF\n");
		return -1;
	}

	return 0;
}

/*
 * bpf_print_header - print trace output header
 */
static void bpf_print_header(void)
{
	printf("%16s-%-8s %5s %5s ", "<TASK>", "PID", "[CPU]", "TYPE");
	if (config.has_id)
		printf(" %8s", "ID");

	printf("%24s x %-24s -> %-24s %s\n",
		"STATE",
		"EVENT",
		"NEXT_STATE",
		"FINAL");

	printf("%16s %-8s %5s %5s ", " | ", " | ", " | ", " | ");

	if (config.has_id)
		printf(" %8s", " | ");
	printf("%24s   %-24s    %-24s %s\n", " | ", " | ", " | ", "|");
}

static inline uint64_t read_field(uint64_t *entry, enum field_id id,
				  const uint8_t *raw,
				  const struct bpf_monitor_ctx *ctx)
{
	const struct field *field = &ctx->field_metadata[id];

	switch (field->size) {
	case 1:
		return entry[id] = *(const uint8_t *)(raw + field->offset);
	case 2:
		return entry[id] = *(const uint16_t *)(raw + field->offset);
	case 4:
		return entry[id] = *(const uint32_t *)(raw + field->offset);
	case 8:
		return entry[id] = *(const uint64_t *)(raw + field->offset);
	}
	return 0;
}

/*
 * handle_event - ring buffer callback for trace events
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct bpf_monitor_ctx *mon_ctx = ctx;
	const uint8_t *raw = data;
	uint64_t entry[FIELD_MAX] = {0};
	const char *comm;

	if (should_stop())
		return 1;

	if (config.has_id)
		read_field(entry, FIELD_ID, raw, mon_ctx);
	read_field(entry, FIELD_PID, raw, mon_ctx);

	if (config.has_id && (config.my_pid == entry[FIELD_ID]))
		return 0;
	else if (config.my_pid == entry[FIELD_PID])
		return 0;

	read_field(entry, FIELD_EVENT_TYPE, raw, mon_ctx);
	read_field(entry, FIELD_CPU, raw, mon_ctx);
	comm = (const char *)(raw + mon_ctx->field_metadata[FIELD_COMM].offset);
	read_field(entry, FIELD_CURR_STATE, raw, mon_ctx);
	read_field(entry, FIELD_EVENT, raw, mon_ctx);

	printf("%16s-%-8"PRIu64" [%.3"PRIu64"] ", comm, entry[FIELD_PID], entry[FIELD_CPU]);
	if (entry[FIELD_EVENT_TYPE] == mon_ctx->trace_types[TRACE_TYPE_ERROR]) {
		printf("error ");
		if (config.has_id)
			printf(" %8"PRIu64"", entry[FIELD_ID]);
		printf(" %24s x %-24s\n",
		       get_state_name(mon_ctx, entry[FIELD_CURR_STATE]),
		       get_event_name(mon_ctx, entry[FIELD_EVENT]));
	} else if (entry[FIELD_EVENT_TYPE] == mon_ctx->trace_types[TRACE_TYPE_EVENT]) {
		printf("event ");
		read_field(entry, FIELD_IS_FINAL, raw, mon_ctx);
		read_field(entry, FIELD_NEXT_STATE, raw, mon_ctx);

		if (config.has_id)
			printf(" %8"PRIu64"", entry[FIELD_ID]);
		printf(" %24s x %-24s -> %-24s %c\n",
		       get_state_name(mon_ctx, entry[FIELD_CURR_STATE]),
		       get_event_name(mon_ctx, entry[FIELD_EVENT]),
		       get_state_name(mon_ctx, entry[FIELD_NEXT_STATE]),
		       entry[FIELD_IS_FINAL] ? 'Y' : 'N');
	}

	return 0;
}

/*
 * extract_enum_names - extract names from a BTF enum
 *
 * Reads enum member names from BTF and stores them in dest array.
 * Returns the number of enum members extracted (excluding the
 * {state/event}_max_NAME entry and trimming the _NAME padding)
 * on success, or -1 on error.
 */
static int extract_enum_names(const struct btf *btf, const char *enum_kind,
			       char dest[][MAX_DA_NAME_LEN], struct bpf_monitor_ctx *ctx)
{
	const struct btf_type *enum_type;
	const struct btf_enum *enums;
	char buf[2 * MAX_DA_NAME_LEN];
	bool arrived_at_last = false;
	int type_id, vlen;
	int count = 0;

	snprintf(buf, sizeof(buf), "%ss_%s", enum_kind, ctx->monitor_name);
	type_id = btf__find_by_name_kind(btf, buf, BTF_KIND_ENUM);
	if (type_id <= 0) {
		debug_msg("bpf: could not find enum '%s' in BTF\n", buf);
		return -1;
	}
	enum_type = btf__type_by_id(btf, type_id);
	if (!enum_type)
		return -1;

	enums = btf_enum(enum_type);
	vlen = btf_vlen(enum_type);

	snprintf(buf, sizeof(buf), "%s_max_%s", enum_kind, ctx->monitor_name);
	for (int i = 0; i < vlen; i++) {
		const char *name = btf__name_by_offset(btf, enums[i].name_off);
		const char *padding;
		size_t name_len;

		if (!name || count >= MAX_ENUMS)
			break;

		/* max value must be the last */
		if (!strcmp(name, buf)) {
			if (i == vlen - 1)
				arrived_at_last = true;
			break;
		}

		padding = strrchr(name, '_');
		name_len = strlen(name);
		if (padding && !strcmp(ctx->monitor_name, padding + 1))
			name_len = (size_t)(padding - name);

		if (!name_len)
			break;

		if (name_len >= MAX_DA_NAME_LEN)
			name_len = MAX_DA_NAME_LEN - 1;
		strncpy(dest[count], name, name_len);
		dest[count][name_len] = '\0';
		count++;
	}

	if (!arrived_at_last) {
		debug_msg("bpf: malformed %ss enum, could fill %d\n", enum_kind, count);
		return -1;
	}

	return count;
}

/*
 * extract_btf_info - extract BTF types information from the monitor
 *
 * Extract state and event names from enums using BTF and extract field
 * offsets for flexible event parsing.
 */
static int extract_btf_info(struct bpf_object *obj, struct bpf_monitor_ctx *ctx)
{
	const struct btf *btf;

	btf = bpf_object__btf(obj);
	if (!btf) {
		err_msg("bpf: no BTF found in BPF object\n");
		return -1;
	}

	if (extract_trace_type_metadata(btf, ctx)) {
		err_msg("bpf: failed to extract trace type metadata\n");
		return -1;
	}

	if (extract_field_metadata(btf, ctx)) {
		err_msg("bpf: failed to extract field metadata\n");
		return -1;
	}

	ctx->num_states = extract_enum_names(btf, "state", ctx->state_names, ctx);
	ctx->num_events = extract_enum_names(btf, "event", ctx->event_names, ctx);
	if (ctx->num_states < 0 || ctx->num_events < 0) {
		err_msg("bpf: failed to extract states (%d) or events names (%d)\n",
			ctx->num_states, ctx->num_events);
		return -1;
	}

	return 0;
}

/*
 * find_bpf_file - search for a BPF object file in a specific subdirectory
 */
static int find_bpf_file(const char *subdir, const char *name, char *path_out, size_t path_len)
{
	char path[MAX_PATH];

	for (int i = 0; bpf_base_paths[i][0]; i++) {
		size_t size = snprintf(path, sizeof(path), "%s/%s/%s.o",
				       bpf_base_paths[i], subdir, name);

		if (size < MAX_PATH && access(path, R_OK) == 0) {
			strncpy(path_out, path, path_len - 1);
			path_out[path_len - 1] = '\0';
			return 1;
		}
	}

	return 0;
}

/*
 * find_bpf_monitor - search for BPF monitor object file in all directories
 */
static int find_bpf_monitor(const char *monitor_name, char *path_out, size_t path_len)
{
	return find_bpf_file("bpf_monitors", monitor_name, path_out, path_len);
}

/*
 * bpf_setup_ring_buffer - set up the ring buffer to trace events
 *
 * Find the ring buffer map and set up the events handler.
 */
static struct ring_buffer *bpf_setup_ring_buffer(struct bpf_object *obj,
						 struct bpf_monitor_ctx *ctx)
{
	struct ring_buffer *rb;
	struct bpf_map *map;
	char ringbuf_name[2 * MAX_DA_NAME_LEN];

	snprintf(ringbuf_name, sizeof(ringbuf_name), "rv_rb_%s", ctx->monitor_name);
	map = bpf_object__find_map_by_name(obj, ringbuf_name);
	if (!map) {
		err_msg("bpf: error finding ring buffer %s\n", ringbuf_name);
		return NULL;
	}

	rb = ring_buffer__new(bpf_map__fd(map), handle_event, ctx, NULL);
	if (!rb) {
		err_msg("bpf: error opening ring buffer: %s\n", strerror(errno));
		return NULL;
	}

	return rb;
}

/*
 * bpf_usage_print_reactors - print available BPF reactors
 */
void bpf_usage_print_reactors(void)
{
	fprintf(stderr, "  available BPF reactors: nop\n");
}

/*
 * bpf_enable_tracing - set the trace_level variable in .rodata
 *
 * Find trace_level in a special section of .rodata and set its value before
 * loading.
 *
 * Returns 0 on success, -1 on error.
 */
static int bpf_enable_tracing(struct bpf_object *obj, int val)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, ".rodata.trace_level");
	size_t data_size;
	int *trace_level;

	if (!map)
		return -1;

	trace_level = bpf_map__initial_value(map, &data_size);
	if (!trace_level || data_size != sizeof(*trace_level))
		return -1;

	*trace_level = val;
	return 0;
}

/*
 * open_bpf_monitor - open and load a BPF monitor object from a file path
 *
 * Returns loaded BPF object on success, NULL on error.
 */
static struct bpf_object *open_bpf_monitor(const char *path, struct bpf_monitor_ctx *ctx)
{
	struct bpf_object *obj = NULL;
	int res;

	LIBBPF_OPTS(bpf_object_open_opts, opts,
		/* Define statically as arch is known, Kconfig may not be available */
#ifdef __x86_64__
		.kconfig = "CONFIG_X86_64=y\n",
#else
		.kconfig = "CONFIG_X86_64=n\n",
#endif
	);

	obj = bpf_object__open_file(path, &opts);
	if (!obj) {
		err_msg("bpf: error opening object: %s\n", strerror(errno));
		return NULL;
	}

	if (config.trace) {
		res = extract_btf_info(obj, ctx);
		if (res || bpf_enable_tracing(obj, ctx->trace_types[TRACE_TYPE_EVENT])) {
			err_msg("bpf: failed to enable tracing\n");
			bpf_object__close(obj);
			return NULL;
		}
	}

	res = bpf_object__load(obj);
	if (res) {
		err_msg("bpf: error loading object: %s\n", strerror(-res));
		bpf_object__close(obj);
		return NULL;
	}

	return obj;
}

/*
 * attach_bpf_handlers - attach all BPF programs
 *
 * Attaches all non-struct_ops programs and stores links in the provided array.
 *
 * Returns fd of enable program on success, -1 on error.
 */
static int attach_bpf_handlers(const char *monitor_name, struct bpf_object *obj,
				struct bpf_link **links, int *link_count)
{
	struct bpf_program *prog;
	int enable_mon_fd = -1;

	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = NULL;
		const char *prog_name;

		/* Special program to initialise the monitor */
		if (!strcmp(bpf_program__name(prog), PROG_ENABLE_MON)) {
			enable_mon_fd = bpf_program__fd(prog);
			continue;
		}

		if (*link_count >= MAX_LINKS) {
			err_msg("bpf: too many programs to attach (%d)\n", *link_count);
			return -1;
		}

		prog_name = bpf_program__name(prog);
		link = bpf_program__attach(prog);
		if (!link) {
			err_msg("bpf: error attaching program '%s': %s\n",
				prog_name, strerror(errno));
			return -1;
		}
		links[(*link_count)++] = link;
	}
	if (enable_mon_fd < 0)
		err_msg("bpf: could not find program %s\n", PROG_ENABLE_MON);
	return enable_mon_fd;
}

/*
 * bpf_run_monitor - load and run a BPF monitor
 *
 * Returns 1 if monitor was found and executed, 0 if not found, -1 on error
 */
int bpf_run_monitor(char *monitor_name, int argc, char **argv)
{
	struct bpf_link *links[MAX_LINKS] = {0};
	struct bpf_monitor_ctx ctx = {0};
	struct ring_buffer *rb = NULL;
	struct bpf_object *obj = NULL;
	int res, link_count = 0, enable_mon_fd, retval = -1;
	char monitor_path[MAX_PATH];

	libbpf_set_print(libbpf_print_fn);
	bpf_fill_base_paths();

	if (!find_bpf_monitor(monitor_name, monitor_path, sizeof(monitor_path)))
		return 0;

	config.is_bpf = true;

	res = bpf_read_enable(monitor_name);
	if (res) {
		err_msg("bpf: monitor %s (BPF) is already enabled\n", monitor_name);
		return -1;
	}

	/* we should be good to go */
	res = parse_arguments(monitor_name, argc, argv);
	if (res)
		mon_usage(1, monitor_name, "bpf: failed parsing arguments");

	strncpy(ctx.monitor_name, monitor_name, sizeof(ctx.monitor_name) - 1);


	obj = open_bpf_monitor(monitor_path, &ctx);
	if (!obj)
		goto cleanup;

	if (config.trace) {
		rb = bpf_setup_ring_buffer(obj, &ctx);
		if (!rb)
			goto cleanup;
	}

	enable_mon_fd = attach_bpf_handlers(monitor_name, obj, links, &link_count);
	if (enable_mon_fd < 0)
		goto cleanup;

	res = bpf_prog_test_run_opts(enable_mon_fd, NULL);
	if (res) {
		err_msg("bpf: error enabling the monitor: %s\n", strerror(-res));
		goto cleanup;
	}

	if (config.trace)
		bpf_print_header();

	while (!should_stop()) {
		if (!config.trace) {
			sleep(1);
			continue;
		}
		res = ring_buffer__poll(rb, 100);
		if (res == -EINTR)
			break;
		if (res < 0) {
			err_msg("bpf: error polling ring buffer: %s\n", strerror(-res));
			goto cleanup;
		}
	}
	retval = 1;

cleanup:
	for (int i = 0; i < link_count; i++)
		bpf_link__destroy(links[i]);

	if (config.trace)
		ring_buffer__free(rb);

	bpf_object__close(obj);

	return retval;
}
