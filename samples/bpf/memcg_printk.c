// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>

static bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	char filename[256];
	int err;

	exiting = false;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_print(libbpf_print_fn);

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "Failed to open BPF object file: %d\n",
			err);
		obj = NULL;
		goto cleanup;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Failed to loading BPF object file: %d\n",
			err);
		goto cleanup;
	}

	map = bpf_object__find_map_by_name(obj, "mcg_ops");
	if (!map) {
		fprintf(stderr, "Failed to find struct_ops map 'mcg_ops'\n");
		err = -ENOENT;
		goto cleanup;
	}

	link = bpf_map__attach_struct_ops(map);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "Failed to attach struct ops: %d\n",
			err);
		link = NULL;
		goto cleanup;
	}

	printf("Press Ctrl+C to exit...\n");

	while (!exiting)
		sleep(1);

	printf("Bye!\n");

cleanup:
	if (link)
		bpf_link__destroy(link);
	if (obj)
		bpf_object__close(obj);

	return err;
}
