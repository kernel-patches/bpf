// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/in6.h>

#include "test_progs.h"
#include "network_helpers.h"
#include "crypto_sanity.skel.h"

#define NS_TEST "crypto_sanity_ns"
#define IPV6_IFACE_ADDR "face::1"
#define UDP_TEST_PORT 7777
static const char plain_text[] = "stringtoencrypt0";
static const char crypted_data[] = "\x5B\x59\x39\xEA\xD9\x7A\x2D\xAD\xA7\xE0\x43" \
				   "\x37\x8A\x77\x17\xB2";

void test_crypto_sanity(void)
{
	LIBBPF_OPTS(bpf_tc_hook, qdisc_hook, .attach_point = BPF_TC_EGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach_enc);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach_dec);
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = crypted_data,
		    .data_size_in = sizeof(crypted_data),
		    .repeat = 1,
	);
	struct nstoken *nstoken = NULL;
	struct crypto_sanity *skel;
	struct sockaddr_in6 addr;
	int sockfd, err, pfd;
	socklen_t addrlen;

	skel = crypto_sanity__open();
	if (!ASSERT_OK_PTR(skel, "skel open"))
		return;

	bpf_program__set_autoload(skel->progs.skb_crypto_setup, true);

	SYS(fail, "ip netns add %s", NS_TEST);
	SYS(fail, "ip -net %s -6 addr add %s/128 dev lo nodad", NS_TEST, IPV6_IFACE_ADDR);
	SYS(fail, "ip -net %s link set dev lo up", NS_TEST);

	err = crypto_sanity__load(skel);
	if (!ASSERT_OK(err, "crypto_sanity__load"))
		goto fail;

	nstoken = open_netns(NS_TEST);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto fail;

	qdisc_hook.ifindex = if_nametoindex("lo");
	if (!ASSERT_GT(qdisc_hook.ifindex, 0, "if_nametoindex lo"))
		goto fail;

	err = crypto_sanity__attach(skel);
	if (!ASSERT_OK(err, "crypto_sanity__attach"))
		goto fail;

	pfd = bpf_program__fd(skel->progs.skb_crypto_setup);
	if (!ASSERT_GT(pfd, 0, "skb_crypto_setup fd"))
		goto fail;

	err = bpf_prog_test_run_opts(pfd, &opts);
	if (!ASSERT_OK(err, "skb_crypto_setup") ||
	    !ASSERT_OK(opts.retval, "skb_crypto_setup retval"))
		goto fail;

	if (!ASSERT_OK(skel->bss->status, "skb_crypto_setup status"))
		goto fail;

	err = bpf_tc_hook_create(&qdisc_hook);
	if (!ASSERT_OK(err, "create qdisc hook"))
		goto fail;

	addrlen = sizeof(addr);
	err = make_sockaddr(AF_INET6, IPV6_IFACE_ADDR, UDP_TEST_PORT,
			    (void *)&addr, &addrlen);
	if (!ASSERT_OK(err, "make_sockaddr"))
		goto fail;

	tc_attach_dec.prog_fd = bpf_program__fd(skel->progs.decrypt_sanity);
	err = bpf_tc_attach(&qdisc_hook, &tc_attach_dec);
	if (!ASSERT_OK(err, "attach decrypt filter"))
		goto fail;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_NEQ(sockfd, -1, "decrypt socket"))
		goto fail;
	err = sendto(sockfd, crypted_data, 16, 0, (void *)&addr, addrlen);
	close(sockfd);
	if (!ASSERT_EQ(err, 16, "decrypt send"))
		goto fail;

	bpf_tc_detach(&qdisc_hook, &tc_attach_dec);
	if (!ASSERT_OK(skel->bss->status, "decrypt status"))
		goto fail;
	if (!ASSERT_STRNEQ(skel->bss->dst, plain_text, sizeof(plain_text), "decrypt"))
		goto fail;

	tc_attach_enc.prog_fd = bpf_program__fd(skel->progs.encrypt_sanity);
	err = bpf_tc_attach(&qdisc_hook, &tc_attach_enc);
	if (!ASSERT_OK(err, "attach encrypt filter"))
		goto fail;

	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_NEQ(sockfd, -1, "encrypt socket"))
		goto fail;
	err = sendto(sockfd, plain_text, 16, 0, (void *)&addr, addrlen);
	close(sockfd);
	if (!ASSERT_EQ(err, 16, "encrypt send"))
		goto fail;

	bpf_tc_detach(&qdisc_hook, &tc_attach_enc);
	if (!ASSERT_OK(skel->bss->status, "encrypt status"))
		goto fail;
	if (!ASSERT_STRNEQ(skel->bss->dst, crypted_data, sizeof(crypted_data), "encrypt"))
		goto fail;

fail:
	if (nstoken) {
		bpf_tc_hook_destroy(&qdisc_hook);
		close_netns(nstoken);
	}
	SYS_NOFAIL("ip netns del " NS_TEST " &> /dev/null");
	crypto_sanity__destroy(skel);
}
