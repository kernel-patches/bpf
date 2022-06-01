// SPDX-License-Identifier: GPL-2.0

#include <sys/types.h>
#include <sys/socket.h>
#include <test_progs.h>
#include <bpf/btf.h>

#include "lsm_cgroup.skel.h"
#include "cgroup_helpers.h"
#include "network_helpers.h"

static __u32 query_prog_cnt(int cgroup_fd, const char *attach_func)
{
	LIBBPF_OPTS(bpf_prog_query_opts, p);
	static struct btf *btf;
	int cnt = 0;
	int i;

	ASSERT_OK(bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &p), "prog_query");

	if (!attach_func)
		return p.prog_cnt;

	/* When attach_func is provided, count the number of progs that
	 * attach to the given symbol.
	 */

	if (!btf)
		btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK(libbpf_get_error(btf), "btf_vmlinux"))
		return -1;

	p.prog_ids = malloc(sizeof(u32) * p.prog_cnt);
	p.prog_attach_flags = malloc(sizeof(u32) * p.prog_cnt);
	ASSERT_OK(bpf_prog_query_opts(cgroup_fd, BPF_LSM_CGROUP, &p), "prog_query");

	for (i = 0; i < p.prog_cnt; i++) {
		struct bpf_prog_info info = {};
		__u32 info_len = sizeof(info);
		int fd;

		fd = bpf_prog_get_fd_by_id(p.prog_ids[i]);
		ASSERT_GE(fd, 0, "prog_get_fd_by_id");
		ASSERT_OK(bpf_obj_get_info_by_fd(fd, &info, &info_len), "prog_info_by_fd");
		close(fd);

		if (info.attach_btf_id ==
		    btf__find_by_name_kind(btf, attach_func, BTF_KIND_FUNC))
			cnt++;
	}

	return cnt;
}

static void test_lsm_cgroup_functional(void)
{
	DECLARE_LIBBPF_OPTS(bpf_prog_attach_opts, attach_opts);
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, update_opts);
	int cgroup_fd, cgroup_fd2, err, fd, prio;
	int listen_fd, client_fd, accepted_fd;
	struct lsm_cgroup *skel = NULL;
	int post_create_prog_fd2 = -1;
	int post_create_prog_fd = -1;
	int bind_link_fd2 = -1;
	int bind_prog_fd2 = -1;
	int alloc_prog_fd = -1;
	int bind_prog_fd = -1;
	int bind_link_fd = -1;
	int clone_prog_fd = -1;
	socklen_t socklen;

	cgroup_fd = test__join_cgroup("/sock_policy");
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto close_skel;

	cgroup_fd2 = create_and_get_cgroup("/sock_policy2");
	if (!ASSERT_GE(cgroup_fd2, 0, "create second cgroup"))
		goto close_skel;

	skel = lsm_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto close_cgroup;

	post_create_prog_fd = bpf_program__fd(skel->progs.socket_post_create);
	post_create_prog_fd2 = bpf_program__fd(skel->progs.socket_post_create2);
	bind_prog_fd = bpf_program__fd(skel->progs.socket_bind);
	bind_prog_fd2 = bpf_program__fd(skel->progs.socket_bind2);
	alloc_prog_fd = bpf_program__fd(skel->progs.socket_alloc);
	clone_prog_fd = bpf_program__fd(skel->progs.socket_clone);

	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_sk_alloc_security"), 0, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 0, "total prog count");
	err = bpf_prog_attach(alloc_prog_fd, cgroup_fd, BPF_LSM_CGROUP, 0);
	if (!ASSERT_OK(err, "attach alloc_prog_fd"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_sk_alloc_security"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 1, "total prog count");

	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_inet_csk_clone"), 0, "prog count");
	err = bpf_prog_attach(clone_prog_fd, cgroup_fd, BPF_LSM_CGROUP, 0);
	if (!ASSERT_OK(err, "attach clone_prog_fd"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_inet_csk_clone"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 2, "total prog count");

	/* Make sure replacing works. */

	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_post_create"), 0, "prog count");
	err = bpf_prog_attach(post_create_prog_fd, cgroup_fd,
			      BPF_LSM_CGROUP, 0);
	if (!ASSERT_OK(err, "attach post_create_prog_fd"))
		goto close_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_post_create"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 3, "total prog count");

	attach_opts.replace_prog_fd = post_create_prog_fd;
	err = bpf_prog_attach_opts(post_create_prog_fd2, cgroup_fd,
				   BPF_LSM_CGROUP, &attach_opts);
	if (!ASSERT_OK(err, "prog replace post_create_prog_fd"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_post_create"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 3, "total prog count");

	/* Try the same attach/replace via link API. */

	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_bind"), 0, "prog count");
	bind_link_fd = bpf_link_create(bind_prog_fd, cgroup_fd,
				       BPF_LSM_CGROUP, NULL);
	if (!ASSERT_GE(bind_link_fd, 0, "link create bind_prog_fd"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_bind"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 4, "total prog count");

	update_opts.old_prog_fd = bind_prog_fd;
	update_opts.flags = BPF_F_REPLACE;

	err = bpf_link_update(bind_link_fd, bind_prog_fd2, &update_opts);
	if (!ASSERT_OK(err, "link update bind_prog_fd"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_bind"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 4, "total prog count");

	/* Attach another instance of bind program to another cgroup.
	 * This should trigger the reuse of the trampoline shim (two
	 * programs attaching to the same btf_id).
	 */

	ASSERT_EQ(query_prog_cnt(cgroup_fd, "bpf_lsm_socket_bind"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd2, "bpf_lsm_socket_bind"), 0, "prog count");
	bind_link_fd2 = bpf_link_create(bind_prog_fd2, cgroup_fd2,
					BPF_LSM_CGROUP, NULL);
	if (!ASSERT_GE(bind_link_fd2, 0, "link create bind_prog_fd2"))
		goto detach_cgroup;
	ASSERT_EQ(query_prog_cnt(cgroup_fd2, "bpf_lsm_socket_bind"), 1, "prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd, NULL), 4, "total prog count");
	ASSERT_EQ(query_prog_cnt(cgroup_fd2, NULL), 1, "total prog count");

	/* AF_UNIX is prohibited. */

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ASSERT_LT(fd, 0, "socket(AF_UNIX)");

	/* AF_INET6 gets default policy (sk_priority). */

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket(SOCK_STREAM)"))
		goto detach_cgroup;

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0,
		  "getsockopt");
	ASSERT_EQ(prio, 123, "sk_priority");

	close(fd);

	/* TX-only AF_PACKET is allowed. */

	ASSERT_LT(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), 0,
		  "socket(AF_PACKET, ..., ETH_P_ALL)");

	fd = socket(AF_PACKET, SOCK_RAW, 0);
	ASSERT_GE(fd, 0, "socket(AF_PACKET, ..., 0)");

	/* TX-only AF_PACKET can not be rebound. */

	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	ASSERT_LT(bind(fd, (struct sockaddr *)&sa, sizeof(sa)), 0,
		  "bind(ETH_P_ALL)");

	close(fd);

	/* Trigger passive open. */

	listen_fd = start_server(AF_INET6, SOCK_STREAM, "::1", 0, 0);
	ASSERT_GE(listen_fd, 0, "start_server");
	client_fd = connect_to_fd(listen_fd, 0);
	ASSERT_GE(client_fd, 0, "connect_to_fd");
	accepted_fd = accept(listen_fd, NULL, NULL);
	ASSERT_GE(accepted_fd, 0, "accept");

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(accepted_fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0,
		  "getsockopt");
	ASSERT_EQ(prio, 234, "sk_priority");

	/* These are replaced and never called. */
	ASSERT_EQ(skel->bss->called_socket_post_create, 0, "called_create");
	ASSERT_EQ(skel->bss->called_socket_bind, 0, "called_bind");

	/* AF_INET6+SOCK_STREAM
	 * AF_PACKET+SOCK_RAW
	 * listen_fd
	 * client_fd
	 * accepted_fd
	 */
	ASSERT_EQ(skel->bss->called_socket_post_create2, 5, "called_create2");

	/* start_server
	 * bind(ETH_P_ALL)
	 */
	ASSERT_EQ(skel->bss->called_socket_bind2, 2, "called_bind2");
	/* Single accept(). */
	ASSERT_EQ(skel->bss->called_socket_clone, 1, "called_clone");

	/* AF_UNIX+SOCK_STREAM (failed)
	 * AF_INET6+SOCK_STREAM
	 * AF_PACKET+SOCK_RAW (failed)
	 * AF_PACKET+SOCK_RAW
	 * listen_fd
	 * client_fd
	 * accepted_fd
	 */
	ASSERT_EQ(skel->bss->called_socket_alloc, 7, "called_alloc");

	/* Make sure other cgroup doesn't trigger the programs. */

	if (!ASSERT_OK(join_cgroup(""), "join root cgroup"))
		goto detach_cgroup;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (!ASSERT_GE(fd, 0, "socket(SOCK_STREAM)"))
		goto detach_cgroup;

	prio = 0;
	socklen = sizeof(prio);
	ASSERT_GE(getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, &socklen), 0,
		  "getsockopt");
	ASSERT_EQ(prio, 0, "sk_priority");

	close(fd);

detach_cgroup:
	ASSERT_GE(bpf_prog_detach2(post_create_prog_fd2, cgroup_fd,
				   BPF_LSM_CGROUP), 0, "detach_create");
	close(bind_link_fd);
	/* Don't close bind_link_fd2, exercise cgroup release cleanup. */
	ASSERT_GE(bpf_prog_detach2(alloc_prog_fd, cgroup_fd,
				   BPF_LSM_CGROUP), 0, "detach_alloc");
	ASSERT_GE(bpf_prog_detach2(clone_prog_fd, cgroup_fd,
				   BPF_LSM_CGROUP), 0, "detach_clone");

close_cgroup:
	close(cgroup_fd);
close_skel:
	lsm_cgroup__destroy(skel);
}

static int field_offset(const char *type, const char *field)
{
	const struct btf_member *memb;
	const struct btf_type *tp;
	const char *name;
	struct btf *btf;
	int btf_id;
	int i;

	btf = btf__load_vmlinux_btf();
	if (!btf)
		return -1;

	btf_id = btf__find_by_name_kind(btf, type, BTF_KIND_STRUCT);
	if (btf_id < 0)
		return -1;

	tp = btf__type_by_id(btf, btf_id);
	memb = btf_members(tp);

	for (i = 0; i < btf_vlen(tp); i++) {
		name = btf__name_by_offset(btf,
					   memb->name_off);
		if (strcmp(field, name) == 0)
			return memb->offset / 8;
		memb++;
	}

	return -1;
}

static bool sk_writable_field(const char *type, const char *field, int size)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		    .expected_attach_type = BPF_LSM_CGROUP);
	struct bpf_insn	insns[] = {
		/* r1 = *(u64 *)(r1 + 0) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0),
		/* r1 = *(u64 *)(r1 + offsetof(struct socket, sk)) */
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, field_offset("socket", "sk")),
		/* r2 = *(u64 *)(r1 + offsetof(struct sock, <field>)) */
		BPF_LDX_MEM(size, BPF_REG_2, BPF_REG_1, field_offset(type, field)),
		/* *(u64 *)(r1 + offsetof(struct sock, <field>)) = r2 */
		BPF_STX_MEM(size, BPF_REG_1, BPF_REG_2, field_offset(type, field)),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	int fd;

	opts.attach_btf_id = libbpf_find_vmlinux_btf_id("socket_post_create",
							opts.expected_attach_type);

	fd = bpf_prog_load(BPF_PROG_TYPE_LSM, NULL, "GPL", insns, ARRAY_SIZE(insns), &opts);
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

static void test_lsm_cgroup_access(void)
{
	ASSERT_FALSE(sk_writable_field("sock_common", "skc_family", BPF_H), "skc_family");
	ASSERT_FALSE(sk_writable_field("sock", "sk_sndtimeo", BPF_DW), "sk_sndtimeo");
	ASSERT_TRUE(sk_writable_field("sock", "sk_priority", BPF_W), "sk_priority");
	ASSERT_TRUE(sk_writable_field("sock", "sk_mark", BPF_W), "sk_mark");
	ASSERT_FALSE(sk_writable_field("sock", "sk_pacing_rate", BPF_DW), "sk_pacing_rate");
}

void test_lsm_cgroup(void)
{
	if (test__start_subtest("functional"))
		test_lsm_cgroup_functional();
	if (test__start_subtest("access"))
		test_lsm_cgroup_access();
}
