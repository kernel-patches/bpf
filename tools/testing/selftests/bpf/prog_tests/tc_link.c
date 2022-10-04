// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Isovalent */

#include <uapi/linux/if_link.h>
#include <test_progs.h>

#include "test_tc_link.skel.h"

#define loopback	1
#define ping_cmd	"ping -q -c1 -w1 127.0.0.1 > /dev/null"

void serial_test_tc_link_base(void)
{
	struct test_tc_link *skel1 = NULL, *skel2 = NULL;
	__u32 prog_fd1, prog_fd2, prog_fd3, prog_fd4;
	__u32 id0 = 0, id1, id2, id3, id4, id5, id6, id7;
	struct bpf_prog_info prog_info;
	struct bpf_link_info link_info;
	__u32 link_info_len = sizeof(link_info);
	__u32 prog_info_len = sizeof(prog_info);
	__u32 prog_cnt, attach_flags = 0;
	struct bpf_query_info progs[4];
	struct bpf_link *link;
	int err;

	skel1 = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel1, "skel_load"))
		goto cleanup;
	prog_fd1 = bpf_program__fd(skel1->progs.tc_handler_in);
	prog_fd2 = bpf_program__fd(skel1->progs.tc_handler_eg);

	skel2 = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel2, "skel_load"))
		goto cleanup;
	prog_fd3 = bpf_program__fd(skel2->progs.tc_handler_in);
	prog_fd4 = bpf_program__fd(skel2->progs.tc_handler_eg);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd1, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info1"))
		goto cleanup;
	id1 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd2, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info2"))
		goto cleanup;
	id2 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd3, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info3"))
		goto cleanup;
	id3 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd4, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info4"))
		goto cleanup;
	id4 = prog_info.id;

	/* Sanity check that we have distinct programs. */
	ASSERT_NEQ(id1, id3, "prog_ids_1_3");
	ASSERT_NEQ(id2, id4, "prog_ids_2_4");
	ASSERT_NEQ(id1, id4, "prog_ids_1_4");

	link = bpf_program__attach_tc(skel1->progs.tc_handler_in, loopback, 1);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel1->links.tc_handler_in = link;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	/* Sanity check that attached ingress BPF link looks as expected. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id1, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, loopback, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_INGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 1, "link_priority");
	ASSERT_NEQ(link_info.id, id0, "link_id");
	id5 = link_info.id;

	/* Updating program under active ingress BPF link works as expected. */
	err = bpf_link__update_program(link, skel2->progs.tc_handler_in);
	if (!ASSERT_OK(err, "link_upd_invalid"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	ASSERT_EQ(link_info.id, id5, "link_id");
	ASSERT_EQ(link_info.prog_id, id3, "link_prog_id");

	link = bpf_program__attach_tc(skel1->progs.tc_handler_eg, loopback, 1);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel1->links.tc_handler_eg = link;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	/* Sanity check that attached egress BPF link looks as expected. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id2, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, loopback, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_EGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 1, "link_priority");
	ASSERT_NEQ(link_info.id, id0, "link_id");
	ASSERT_NEQ(link_info.id, id5, "link_id");
	id6 = link_info.id;

	/* Updating program under active egress BPF link works as expected. */
	err = bpf_link__update_program(link, skel2->progs.tc_handler_eg);
	if (!ASSERT_OK(err, "link_upd_invalid"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	ASSERT_EQ(link_info.id, id6, "link_id");
	ASSERT_EQ(link_info.prog_id, id4, "link_prog_id");

	/* BPF link is not allowed to replace another BPF link. */
	link = bpf_program__attach_tc(skel2->progs.tc_handler_eg, loopback, 1);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	/* BPF link can be attached with different prio to available slot however. */
	link = bpf_program__attach_tc(skel2->progs.tc_handler_eg, loopback, 2);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	/* Sanity check that 2nd attached egress BPF link looks as expected. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id4, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, loopback, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_EGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 2, "link_priority");
	ASSERT_NEQ(link_info.id, id6, "link_id");

	/* We destroy link, and reattach with auto-allocated prio. */
	bpf_link__destroy(link);

	link = bpf_program__attach_tc(skel2->progs.tc_handler_eg, loopback, 0);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup_link;

	/* Sanity check that egress BPF link looks as expected and got prio 2. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id4, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, loopback, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_EGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 2, "link_priority");
	ASSERT_NEQ(link_info.id, id6, "link_id");
	id7 = link_info.id;

	/* Sanity check query API on what progs we have attached. */
	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_link;

	ASSERT_EQ(prog_cnt, 2, "prog_cnt");

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_link;

	ASSERT_EQ(prog_cnt, 2, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id4, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, id6, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, id4, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, id7, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 2, "prog[1]_prio");
	ASSERT_EQ(progs[2].prog_id, 0, "prog[2]_id");
	ASSERT_EQ(progs[2].link_id, 0, "prog[2]_link");
	ASSERT_EQ(progs[2].prio, 0, "prog[2]_prio");

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_link;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id3, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, id5, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, 0, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 0, "prog[1]_prio");

cleanup_link:
	bpf_link__destroy(link);
cleanup:
	test_tc_link__destroy(skel1);
	test_tc_link__destroy(skel2);
}

void serial_test_tc_link_detach(void)
{
	struct bpf_prog_info prog_info;
	struct bpf_link_info link_info;
	struct test_tc_link *skel;
	__u32 prog_info_len = sizeof(prog_info);
	__u32 link_info_len = sizeof(link_info);
	__u32 prog_cnt, attach_flags = 0;
	__u32 prog_fd, id, id2;
	struct bpf_link *link;
	int err;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;
	prog_fd = bpf_program__fd(skel->progs.tc_handler_in);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info"))
		goto cleanup;
	id = prog_info.id;

	link = bpf_program__attach_tc(skel->progs.tc_handler_in, loopback, 0);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel->links.tc_handler_in = link;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	/* Sanity check that attached ingress BPF link looks as expected. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, loopback, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_INGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 1, "link_priority");
	id2 = link_info.id;

	/* Sanity check query API that one prog is attached. */
	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");

	err = bpf_link__detach(link);
	if (!ASSERT_OK(err, "link_detach"))
		goto cleanup;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	/* Sanity check that defunct detached link looks as expected. */
	ASSERT_EQ(link_info.type, BPF_LINK_TYPE_TC, "link_type");
	ASSERT_EQ(link_info.prog_id, id, "link_prog_id");
	ASSERT_EQ(link_info.tc.ifindex, 0, "link_ifindex");
	ASSERT_EQ(link_info.tc.attach_type, BPF_NET_INGRESS, "link_attach_type");
	ASSERT_EQ(link_info.tc.priority, 1, "link_priority");
	ASSERT_EQ(link_info.id, id2, "link_id");

	/* Sanity check query API that no prog is attached. */
	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	ASSERT_EQ(err, -ENOENT, "prog_cnt");
cleanup:
	test_tc_link__destroy(skel);
}

void serial_test_tc_link_opts(void)
{
	DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, opta);
	DECLARE_LIBBPF_OPTS(bpf_prog_detach_opts, optd);
	__u32 prog_fd1, prog_fd2, id1, id2;
	struct bpf_prog_info prog_info;
	struct test_tc_link *skel;
	__u32 prog_info_len = sizeof(prog_info);
	__u32 prog_cnt, attach_flags = 0;
	struct bpf_query_info progs[4];
	int err, prio;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;
	prog_fd1 = bpf_program__fd(skel->progs.tc_handler_in);
	prog_fd2 = bpf_program__fd(skel->progs.tc_handler_eg);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd1, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info1"))
		goto cleanup;
	id1 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd2, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info2"))
		goto cleanup;
	id2 = prog_info.id;

	ASSERT_NEQ(id1, id2, "prog_ids_1_2");

	/* Sanity check query API that nothing is attached. */
	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	ASSERT_EQ(prog_cnt, 0, "prog_cnt");
	ASSERT_EQ(err, -ENOENT, "prog_query");

	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	ASSERT_EQ(prog_cnt, 0, "prog_cnt");
	ASSERT_EQ(err, -ENOENT, "prog_query");

	/* Sanity check that attaching with given prio works. */
	opta.flags = 0;
	opta.attach_priority = prio = 1;
	err = bpf_prog_attach_opts(prog_fd1, loopback, BPF_NET_INGRESS, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_attach"))
		goto cleanup;

	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id1, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, 0, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 0, "prog[1]_prio");

	/* We cannot override unless we add replace flag. */
	opta.flags = 0;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd2, loopback, BPF_NET_INGRESS, &opta);
	if (!ASSERT_ERR(err, "prog_attach_fail"))
		goto cleanup_detach;

	opta.flags = BPF_F_REPLACE;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd2, loopback, BPF_NET_INGRESS, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_replace"))
		goto cleanup_detach;

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id2, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, 0, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 0, "prog[1]_prio");

	/* Check auto-assignment for priority. */
	opta.flags = 0;
	opta.attach_priority = 0;
	err = bpf_prog_attach_opts(prog_fd1, loopback, BPF_NET_INGRESS, &opta);
	if (!ASSERT_EQ(err, 2, "prog_replace"))
		goto cleanup_detach;

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach2;

	ASSERT_EQ(prog_cnt, 2, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id2, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, id1, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 2, "prog[1]_prio");
	ASSERT_EQ(progs[2].prog_id, 0, "prog[2]_id");
	ASSERT_EQ(progs[2].link_id, 0, "prog[2]_link");
	ASSERT_EQ(progs[2].prio, 0, "prog[2]_prio");

	/* Remove the 1st program, so the 2nd becomes 1st in line. */
	prio = 2;
	optd.attach_priority = 1;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_INGRESS, &optd);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup_detach;

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id1, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 2, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, 0, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 0, "prog[1]_prio");

	/* Add back higher prio program, so 1st becomes 2nd in line.
	 * Replace also works if nothing was attached at the given prio.
	 */
	opta.flags = BPF_F_REPLACE;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd2, loopback, BPF_NET_INGRESS, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_replace"))
		goto cleanup_detach;

	prio = 1;
	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach2;

	ASSERT_EQ(prog_cnt, 2, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id2, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, id1, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 2, "prog[1]_prio");
	ASSERT_EQ(progs[2].prog_id, 0, "prog[2]_id");
	ASSERT_EQ(progs[2].link_id, 0, "prog[2]_link");
	ASSERT_EQ(progs[2].prio, 0, "prog[2]_prio");

	optd.attach_priority = 2;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_INGRESS, &optd);
	ASSERT_OK(err, "prog_detach");

	optd.attach_priority = 1;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_INGRESS, &optd);
	ASSERT_OK(err, "prog_detach");

	/* Expected to be empty again. */
	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_INGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	ASSERT_EQ(prog_cnt, 0, "prog_cnt");
	ASSERT_EQ(err, -ENOENT, "prog_query");
	goto cleanup;

cleanup_detach:
	optd.attach_priority = prio;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_INGRESS, &optd);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup;
cleanup:
	test_tc_link__destroy(skel);
	return;
cleanup_detach2:
	optd.attach_priority = 2;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_INGRESS, &optd);
	ASSERT_OK(err, "prog_detach");
	goto cleanup_detach;
}

void serial_test_tc_link_mix(void)
{
	DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, opta);
	DECLARE_LIBBPF_OPTS(bpf_prog_detach_opts, optd);
	__u32 prog_fd1, prog_fd2, id1, id2, id3;
	struct test_tc_link *skel;
	struct bpf_link *link;
	struct bpf_prog_info prog_info;
	struct bpf_link_info link_info;
	__u32 link_info_len = sizeof(link_info);
	__u32 prog_info_len = sizeof(prog_info);
	__u32 prog_cnt, attach_flags = 0;
	struct bpf_query_info progs[4];
	int err;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;
	prog_fd1 = bpf_program__fd(skel->progs.tc_handler_in);
	prog_fd2 = bpf_program__fd(skel->progs.tc_handler_eg);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd1, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info1"))
		goto cleanup;
	id1 = prog_info.id;

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_obj_get_info_by_fd(prog_fd2, &prog_info, &prog_info_len);
	if (!ASSERT_OK(err, "fd_info2"))
		goto cleanup;
	id2 = prog_info.id;

	ASSERT_NEQ(id1, id2, "prog_ids_1_2");

	/* Sanity check that attaching with given prio works. */
	opta.flags = 0;
	opta.attach_priority = 42;
	err = bpf_prog_attach_opts(prog_fd1, loopback, BPF_NET_EGRESS, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_attach"))
		goto cleanup;

	prog_cnt = 0;
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     NULL, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 1, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id1, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, 0, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 42, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, 0, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 0, "prog[1]_prio");

	/* Sanity check that attaching link with same prio will fail. */
	link = bpf_program__attach_tc(skel->progs.tc_handler_eg, loopback, 42);
	if (!ASSERT_ERR_PTR(link, "link_attach_should_fail")) {
		bpf_link__destroy(link);
		goto cleanup;
	}

	/* Different prio on unused slot works of course. */
	link = bpf_program__attach_tc(skel->progs.tc_handler_eg, loopback, 0);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel->links.tc_handler_eg = link;

	memset(&link_info, 0, sizeof(link_info));
	err = bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &link_info_len);
	if (!ASSERT_OK(err, "link_info"))
		goto cleanup;

	ASSERT_EQ(link_info.prog_id, id2, "link_prog_id");
	id3 = link_info.id;

	memset(progs, 0, sizeof(progs));
	prog_cnt = ARRAY_SIZE(progs);
	err = bpf_prog_query(loopback, BPF_NET_EGRESS, 0, &attach_flags,
			     progs, &prog_cnt);
	if (!ASSERT_OK(err, "prog_query"))
		goto cleanup_detach;

	ASSERT_EQ(prog_cnt, 2, "prog_cnt");
	ASSERT_EQ(progs[0].prog_id, id2, "prog[0]_id");
	ASSERT_EQ(progs[0].link_id, id3, "prog[0]_link");
	ASSERT_EQ(progs[0].prio, 1, "prog[0]_prio");
	ASSERT_EQ(progs[1].prog_id, id1, "prog[1]_id");
	ASSERT_EQ(progs[1].link_id, 0, "prog[1]_link");
	ASSERT_EQ(progs[1].prio, 42, "prog[1]_prio");
	ASSERT_EQ(progs[2].prog_id, 0, "prog[2]_id");
	ASSERT_EQ(progs[2].link_id, 0, "prog[2]_link");
	ASSERT_EQ(progs[2].prio, 0, "prog[2]_prio");

	/* Sanity check that attaching non-link with same prio as link will fail. */
	opta.flags = BPF_F_REPLACE;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd1, loopback, BPF_NET_EGRESS, &opta);
	if (!ASSERT_ERR(err, "prog_attach_should_fail"))
		goto cleanup_detach;

	opta.flags = 0;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd1, loopback, BPF_NET_EGRESS, &opta);
	if (!ASSERT_ERR(err, "prog_attach_should_fail"))
		goto cleanup_detach;

cleanup_detach:
	optd.attach_priority = 42;
	err = bpf_prog_detach_opts(0, loopback, BPF_NET_EGRESS, &optd);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup;
cleanup:
	test_tc_link__destroy(skel);
}

void serial_test_tc_link_run_base(void)
{
	struct test_tc_link *skel;
	struct bpf_link *link;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	link = bpf_program__attach_tc(skel->progs.tc_handler_eg, loopback, 0);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;
	skel->links.tc_handler_eg = link;

	link = bpf_program__attach_tc(skel->progs.tc_handler_in, loopback, 0);
	if (!ASSERT_OK_PTR(link, "link_attach"))
		goto cleanup;

	CHECK_FAIL(system(ping_cmd));
	ASSERT_EQ(skel->bss->run, 3, "run32_value");

	bpf_link__destroy(link);
	skel->bss->run = 0;

	CHECK_FAIL(system(ping_cmd));
	ASSERT_EQ(skel->bss->run, 2, "run32_value");
cleanup:
	test_tc_link__destroy(skel);
}

void tc_link_run_chain(int location, bool chain_tc_old)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = loopback);
	DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, opta);
	DECLARE_LIBBPF_OPTS(bpf_prog_detach_opts, optd);
	bool hook_created = false, tc_attached = false;
	__u32 prog_fd1, prog_fd2, prog_fd3;
	struct test_tc_link *skel;
	int err;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		goto cleanup;

	prog_fd1 = bpf_program__fd(skel->progs.tc_handler_in);
	prog_fd2 = bpf_program__fd(skel->progs.tc_handler_eg);
	prog_fd3 = bpf_program__fd(skel->progs.tc_handler_old);

	if (chain_tc_old) {
		tc_hook.attach_point = location == BPF_NET_INGRESS ?
				       BPF_TC_INGRESS : BPF_TC_EGRESS;
		err = bpf_tc_hook_create(&tc_hook);
		if (err == 0)
			hook_created = true;
		err = err == -EEXIST ? 0 : err;
		if (!ASSERT_OK(err, "bpf_tc_hook_create"))
			goto cleanup;

		tc_opts.prog_fd = prog_fd3;
		err = bpf_tc_attach(&tc_hook, &tc_opts);
		if (!ASSERT_OK(err, "bpf_tc_attach"))
			goto cleanup;
		tc_attached = true;
	}

	opta.flags = 0;
	opta.attach_priority = 1;
	err = bpf_prog_attach_opts(prog_fd1, loopback, location, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_attach"))
		goto cleanup;

	opta.flags = 0;
	opta.attach_priority = 2;
	err = bpf_prog_attach_opts(prog_fd2, loopback, location, &opta);
	if (!ASSERT_EQ(err, opta.attach_priority, "prog_attach"))
		goto cleanup_detach;

	CHECK_FAIL(system(ping_cmd));
	ASSERT_EQ(skel->bss->run, chain_tc_old ? 7 : 3, "run32_value");

	skel->bss->run = 0;

	optd.attach_priority = 2;
	err = bpf_prog_detach_opts(0, loopback, location, &optd);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup_detach;

	CHECK_FAIL(system(ping_cmd));
	ASSERT_EQ(skel->bss->run, chain_tc_old ? 5 : 1, "run32_value");

cleanup_detach:
	optd.attach_priority = 1;
	err = bpf_prog_detach_opts(0, loopback, location, &optd);
	if (!ASSERT_OK(err, "prog_detach"))
		goto cleanup;
cleanup:
	if (tc_attached) {
		tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
		err = bpf_tc_detach(&tc_hook, &tc_opts);
		ASSERT_OK(err, "bpf_tc_detach");
	}
	if (hook_created) {
		tc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&tc_hook);
	}
	test_tc_link__destroy(skel);
}

void serial_test_tc_link_run_chain(void)
{
	tc_link_run_chain(BPF_NET_INGRESS, false);
	tc_link_run_chain(BPF_NET_EGRESS, false);

	tc_link_run_chain(BPF_NET_INGRESS, true);
	tc_link_run_chain(BPF_NET_EGRESS, true);
}
