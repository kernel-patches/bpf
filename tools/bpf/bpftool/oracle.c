// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "main.h"

struct tnum {
	__u64 value;
	__u64 mask;
};

struct bpf_reg_oracle_state {
	bool scalar;
	bool ptr_not_null;

	struct tnum var_off;
	__s64 smin_value;
	__s64 smax_value;
	__u64 umin_value;
	__u64 umax_value;
	__s32 s32_min_value;
	__s32 s32_max_value;
	__u32 u32_min_value;
	__u32 u32_max_value;
};

struct bpf_oracle_state {
	struct bpf_reg_oracle_state regs[MAX_BPF_REG - 1];
};

static void print_register_state(int i, struct bpf_reg_oracle_state *reg)
{
	if (!reg->scalar && !reg->ptr_not_null)
		return;

	printf("R%d=", i);
	if (reg->scalar) {
		printf("scalar(u64=[%llu; %llu], s64=[%lld; %lld], u32=[%u; %u], s32=[%d; %d]",
		       reg->umin_value, reg->umax_value, reg->smin_value, reg->smax_value,
		       reg->u32_min_value, reg->u32_max_value, reg->s32_min_value,
		       reg->s32_max_value);
		printf(", var_off=(%#llx; %#llx)", reg->var_off.value, reg->var_off.mask);
	} else if (reg->ptr_not_null) {
		printf("ptr");
	} else {
		printf("unknown");
	}
	printf("\n");
}

static int
oracle_map_dump(int fd, struct bpf_map_info *info, bool show_header)
{
	struct bpf_oracle_state value = {};
	unsigned int num_elems = 0;
	__u32 key, *prev_key = NULL;
	int err, i;

	while (true) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}
		if (bpf_map_lookup_elem(fd, &key, &value)) {
			printf("<no entry>");
			continue;
		}
		printf("State %u:\n", key);
		for (i = 0; i < MAX_BPF_REG - 1; i++)
			print_register_state(i, &value.regs[i]);
		printf("\n");
		num_elems++;
		prev_key = &key;
	}

	printf("Found %u state%s\n", num_elems,
	       num_elems != 1 ? "s" : "");

	close(fd);
	return err;
}

static int do_dump(int argc, char **argv)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	int nb_fds, i, err;
	int *fds = NULL;

	fds = malloc(sizeof(int));
	if (!fds) {
		p_err("mem alloc failed");
		return -1;
	}
	nb_fds = map_parse_fds(&argc, &argv, &fds, BPF_F_RDONLY);
	if (nb_fds < 1)
		goto exit_free;

	for (i = 0; i < nb_fds; i++) {
		if (bpf_map_get_info_by_fd(fds[i], &info, &len)) {
			p_err("can't get map info: %s", strerror(errno));
			break;
		}
		if (info.type != BPF_MAP_TYPE_ARRAY || info.key_size != sizeof(__u32) ||
		    info.value_size != sizeof(struct bpf_oracle_state)) {
			p_err("not an oracle map");
			break;
		}
		err = oracle_map_dump(fds[i], &info, nb_fds > 1);
		if (i != nb_fds - 1)
			printf("\n");

		if (err)
			break;
		close(fds[i]);
	}

	for (; i < nb_fds; i++)
		close(fds[i]);
exit_free:
	free(fds);
	return 0;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s dump       MAP\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_MAP "\n"
		"       " HELP_SPEC_OPTIONS " |\n"
		"                    {-f|--bpffs} | {-n|--nomount} }\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "help",	do_help },
	{ "dump",	do_dump },
	{ 0 }
};

int do_oracle(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
