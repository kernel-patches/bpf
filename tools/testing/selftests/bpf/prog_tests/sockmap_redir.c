#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/vm_sockets.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_progs.h"
#include "sockmap_helpers.h"
#include "test_sockmap_listen.skel.h"

enum prog_kind {
	SK_MSG_EGRESS,
	SK_MSG_INGRESS,
	SK_SKB_EGRESS,
	SK_SKB_INGRESS,
};

struct {
	enum prog_kind prog_kind;
	const char *in, *out;
} supported[] = {
	/* Send to local: TCP -> any but vsock */
	{ SK_MSG_INGRESS,	"tcp",	"tcp"	},
	{ SK_MSG_INGRESS,	"tcp",	"udp"	},
	{ SK_MSG_INGRESS,	"tcp",	"u_str"	},
	{ SK_MSG_INGRESS,	"tcp",	"u_dgr"	},
	/* Send to egress: TCP -> TCP */
	{ SK_MSG_EGRESS,	"tcp",	"tcp"	},
	/* Ingress to egress: any -> any */
	{ SK_SKB_EGRESS,	"any",	"any"	},
	/* Ingress to local: any -> any but vsock */
	{ SK_SKB_INGRESS,	"any",	"tcp"	},
	{ SK_SKB_INGRESS,	"any",	"udp"	},
	{ SK_SKB_INGRESS,	"any",	"u_str"	},
	{ SK_SKB_INGRESS,	"any",	"u_dgr"	},
};

enum {
	SEND_INNER = 0,
	SEND_OUTER,
};

enum {
	RECV_INNER = 0,
	RECV_OUTER,
};

enum map_kind {
	SOCKMAP,
	SOCKHASH,
};

struct redir_spec {
	const char *name;
	int idx_send;
	int idx_recv;
	enum prog_kind prog_kind;
};

struct socket_spec {
	int family;
	int sotype;
	int send_flags;
	int in[2];
	int out[2];
};

static int socket_spec_pairs(struct socket_spec *s)
{
	return create_socket_pairs(s->family, s->sotype,
				   &s->in[0], &s->out[0],
				   &s->in[1], &s->out[1]);
}

static void socket_spec_close(struct socket_spec *s)
{
	xclose(s->in[0]);
	xclose(s->in[1]);
	xclose(s->out[0]);
	xclose(s->out[1]);
}

static void get_redir_params(struct redir_spec *redir,
			     struct test_sockmap_listen *skel,
			     int *prog_fd, enum bpf_attach_type *attach_type,
			     bool *ingress_flag)
{
	enum prog_kind kind = redir->prog_kind;
	struct bpf_program *prog;
	bool sk_msg;

	sk_msg = kind == SK_MSG_INGRESS || kind == SK_MSG_EGRESS;
	prog = sk_msg ? skel->progs.prog_msg_verdict : skel->progs.prog_skb_verdict;

	*prog_fd = bpf_program__fd(prog);
	*attach_type = sk_msg ? BPF_SK_MSG_VERDICT : BPF_SK_SKB_VERDICT;
	*ingress_flag = kind == SK_MSG_INGRESS || kind == SK_SKB_INGRESS;
}

static void test_send_redir_recv(int sd_send, int send_flags, int sd_in,
				 int sd_out, int sd_recv, int map_in, int map_out)
{
	char *send_buf = "ab";
	char recv_buf = '\0';
	ssize_t n, len = 1;

	if (xbpf_map_update_elem(map_in, &u32(0), &u64(sd_in), BPF_NOEXIST))
		return;

	if (xbpf_map_update_elem(map_out, &u32(0), &u64(sd_out), BPF_NOEXIST))
		goto del_in;

	/* Last byte is OOB data when send_flags has MSG_OOB bit set */
	if (send_flags & MSG_OOB)
		len++;
	n = send(sd_send, send_buf, len, send_flags);
	if (n >= 0 && n < len)
		FAIL("incomplete send");
	if (n < len && errno != EACCES) {
		FAIL_ERRNO("send");
		goto out;
	}

	/* sk_msg redirect combo not supported */
	if (errno == EACCES) {
		test__skip();
		goto out;
	}

	n = recv_timeout(sd_recv, &recv_buf, 1, 0, IO_TIMEOUT_SEC);
	if (n != 1) {
		FAIL_ERRNO("recv");
		goto out;
	}
	if (recv_buf != send_buf[0])
		FAIL("recv: payload check, %02x != %02x", recv_buf, send_buf[0]);

	if (send_flags & MSG_OOB) {
		/* Check that we can't read OOB while in sockmap */
		errno = 0;
		n = recv(sd_out, &recv_buf, 1, MSG_OOB | MSG_DONTWAIT);
		if (n != -1)
			FAIL("recv(MSG_OOB): expected failure: retval=%zd errno=%d",
			     n, errno);

		/* Remove sd_out from sockmap */
		xbpf_map_delete_elem(map_out, &u32(0));

		/* Check that OOB was dropped on redirect */
		errno = 0;
		n = recv(sd_out, &recv_buf, 1, MSG_OOB | MSG_DONTWAIT);
		if (n != -1)
			FAIL("recv(MSG_OOB): expected failure: retval=%zd errno=%d",
			     n, errno);

		goto del_in;
	}
out:
	xbpf_map_delete_elem(map_out, &u32(0));
del_in:
	xbpf_map_delete_elem(map_in, &u32(0));
}

static bool is_supported(enum prog_kind prog_kind, const char *in, const char *out)
{
	for (int i = 0; i < ARRAY_SIZE(supported); ++i)	{
		if (supported[i].prog_kind == prog_kind &&
		    (!strcmp(supported[i].in, "any") || strstr(in, supported[i].in)) &&
		    (!strcmp(supported[i].out, "any") || strstr(out, supported[i].out)))
			return true;
	}

	return false;
}

static void test_socket(enum map_kind map_kind, struct redir_spec *redir,
			int map_in, int map_out, struct socket_spec *s_in,
			struct socket_spec *s_out)
{
	int fd_in, fd_out, fd_send, fd_recv, send_flags;
	const char *in_str, *out_str;
	char s[MAX_TEST_NAME];

	fd_in = s_in->in[0];
	fd_out = s_out->out[0];
	fd_send = s_in->in[redir->idx_send];
	fd_recv = s_out->out[redir->idx_recv];
	send_flags = s_in->send_flags;

	in_str = socket_kind_to_str(fd_in);
	out_str = socket_kind_to_str(fd_out);

	snprintf(s, sizeof(s),
		 "%-4s %-17s %-5s → %-5s%6s",
		 /* hash sk_skb-to-ingress u_str → v_str (OOB) */
		 map_kind == SOCKMAP ? "map" : "hash",
		 redir->name,
		 in_str,
		 out_str,
		 send_flags & MSG_OOB ? "(OOB)" : "");

	if (!test__start_subtest(s))
		return;

	if (!is_supported(redir->prog_kind, in_str, out_str)) {
		test__skip();
		return;
	}

	test_send_redir_recv(fd_send, send_flags, fd_in, fd_out, fd_recv,
			     map_in, map_out);
}

static void test_redir(enum map_kind map_kind, struct redir_spec *redir,
		       int map_in, int map_out)
{
	struct socket_spec *s, sockets[] = {
		{ AF_INET, SOCK_STREAM },
		// { AF_INET, SOCK_STREAM, MSG_OOB },	/* Known to be broken */
		{ AF_INET6, SOCK_STREAM },
		{ AF_INET, SOCK_DGRAM },
		{ AF_INET6, SOCK_DGRAM },
		{ AF_UNIX, SOCK_STREAM },
		{ AF_UNIX, SOCK_STREAM, MSG_OOB },
		{ AF_UNIX, SOCK_DGRAM },
		// { AF_UNIX, SOCK_SEQPACKET},		/* Not supported */
		{ AF_VSOCK, SOCK_STREAM },
		// { AF_VSOCK, SOCK_DGRAM },		/* Not supported */
		{ AF_VSOCK, SOCK_SEQPACKET },
	};

	for (s = sockets; s < sockets + ARRAY_SIZE(sockets); s++)
		if (socket_spec_pairs(s))
			goto out;

	/* Intra-proto */
	for (s = sockets; s < sockets + ARRAY_SIZE(sockets); s++)
		test_socket(map_kind, redir, map_in, map_out, s, s);

	/* Cross-proto */
	for (int i = 0; i < ARRAY_SIZE(sockets); i++) {
		for (int j = 0; j < ARRAY_SIZE(sockets); j++) {
			struct socket_spec *in = &sockets[i];
			struct socket_spec *out = &sockets[j];

			/* Skip intra-proto and between variants */
			if (out->send_flags ||
			    (in->family == out->family &&
			     in->sotype == out->sotype))
				continue;

			test_socket(map_kind, redir, map_in, map_out, in, out);
		}
	}
out:
	while (--s >= sockets)
		socket_spec_close(s);
}

static void test_map(enum map_kind map_kind)
{
	struct redir_spec *r, redirs[] = {
		{ "sk_msg-to-egress", SEND_INNER, RECV_OUTER, SK_MSG_EGRESS },
		{ "sk_msg-to-ingress", SEND_INNER, RECV_INNER, SK_MSG_INGRESS },
		{ "sk_skb-to-egress", SEND_OUTER, RECV_OUTER, SK_SKB_EGRESS },
		{ "sk_skb-to-ingress", SEND_OUTER, RECV_INNER, SK_SKB_INGRESS },
	};

	for (r = redirs; r < redirs + ARRAY_SIZE(redirs); r++) {
		struct test_sockmap_listen *skel;
		enum bpf_attach_type attach_type;
		int prog, map_in, map_out;

		skel = test_sockmap_listen__open_and_load();
		if (!skel) {
			FAIL("open_and_load");
			return;
		}

		if (map_kind == SOCKMAP) {
			skel->bss->test_sockmap = true;
			map_out = bpf_map__fd(skel->maps.sock_map);
		} else {
			skel->bss->test_sockmap = false;
			map_out = bpf_map__fd(skel->maps.sock_hash);
		}

		map_in = bpf_map__fd(skel->maps.nop_map);
		get_redir_params(r, skel, &prog, &attach_type,
				 &skel->bss->test_ingress);

		if (xbpf_prog_attach(prog, map_in, attach_type, 0))
			return;

		test_redir(map_kind, r, map_in, map_out);

		if (xbpf_prog_detach2(prog, map_in, attach_type))
			return;

		test_sockmap_listen__destroy(skel);
	}
}

void serial_test_sockmap_redir(void)
{
	test_map(SOCKMAP);
	test_map(SOCKHASH);
}
