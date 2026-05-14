// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

#define BTF_IDS_PATH "/sys/kernel/tracing/events/sched/sched_switch/btf_ids"

struct btf_ids_info {
	__u32 obj_id;
	__u32 raw_id;
	__u32 tp_id;
};

static int read_btf_ids(struct btf_ids_info *info)
{
	char buf[256];
	int fd, n;

	fd = open(BTF_IDS_PATH, O_RDONLY);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -EIO;
	buf[n] = '\0';

	if (sscanf(buf,
		   "btf_obj_id: %u\nraw_btf_id: %u\ntp_btf_id: %u\n",
		   &info->obj_id, &info->raw_id, &info->tp_id) != 3)
		return -EINVAL;
	return 0;
}

void test_tp_btf_ids(void)
{
	const struct btf_type *proto_t, *rec_t;
	const struct btf_param *params;
	struct btf_ids_info info;
	struct btf *btf;
	const char *name;
	int err;

	err = read_btf_ids(&info);
	if (!ASSERT_OK(err, "read btf_ids"))
		return;

	ASSERT_EQ(info.obj_id, 1, "obj_id is vmlinux");
	ASSERT_GT(info.raw_id, 0, "raw_id non-zero");
	ASSERT_GT(info.tp_id, 0, "tp_id non-zero");

	btf = btf__load_from_kernel_by_id(info.obj_id);
	if (!ASSERT_OK_PTR(btf, "load vmlinux BTF"))
		return;

	proto_t = btf__type_by_id(btf, info.raw_id);
	if (!ASSERT_OK_PTR(proto_t, "raw type_by_id"))
		goto out;
	if (!ASSERT_TRUE(btf_is_func_proto(proto_t), "is func_proto"))
		goto out;

	/*
	 * sched_switch: void *__data, bool preempt, struct task_struct *prev,
	 * struct task_struct *next, unsigned int prev_state
	 */
	ASSERT_EQ(btf_vlen(proto_t), 5, "func_proto arg count");
	params = btf_params(proto_t);
	ASSERT_STREQ(btf__name_by_offset(btf, params[0].name_off), "__data", "arg0 name");
	ASSERT_STREQ(btf__name_by_offset(btf, params[1].name_off), "preempt", "arg1 name");
	ASSERT_STREQ(btf__name_by_offset(btf, params[2].name_off), "prev", "arg2 name");
	ASSERT_STREQ(btf__name_by_offset(btf, params[3].name_off), "next", "arg3 name");
	ASSERT_STREQ(btf__name_by_offset(btf, params[4].name_off), "prev_state", "arg4 name");

	rec_t = btf__type_by_id(btf, info.tp_id);
	if (!ASSERT_OK_PTR(rec_t, "tp type_by_id"))
		goto out;
	if (!ASSERT_TRUE(btf_is_struct(rec_t), "tp is struct"))
		goto out;
	name = btf__name_by_offset(btf, rec_t->name_off);
	ASSERT_STREQ(name, "trace_event_raw_sched_switch", "tp struct name");
out:
	btf__free(btf);
}
