// SPDX-License-Identifier: GPL-2.0
/*
 * BPF monitor support: allows rv to control BPF monitors.
 *
 * Copyright (C) 2026 Red Hat Inc, Gabriele Monaco <gmonaco@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>
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
