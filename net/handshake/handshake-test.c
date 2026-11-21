// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Oracle and/or its affiliates.
 *
 * KUnit test of the handshake upcall mechanism.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>

#include <linux/kernel.h>

#include <net/sock.h>
#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/netns/generic.h>
#include <net/handshake.h>

#include <uapi/linux/handshake.h>
#include "handshake.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static int test_accept_func(struct handshake_req *req, struct genl_info *info,
			    int fd)
{
	return 0;
}

static void test_done_func(struct handshake_req *req, int status,
			   struct genl_info *info)
{
}

struct handshake_req_alloc_test_param {
	const char			*desc;
	struct handshake_proto		*proto;
	gfp_t				gfp;
	bool				expect_success;
};

static struct handshake_proto handshake_req_alloc_proto_2 = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_NONE,
};

static struct handshake_proto handshake_req_alloc_proto_3 = {
	.hp_handler_class	= __HANDSHAKE_HANDLER_CLASS_MAX,
};

static struct handshake_proto handshake_req_alloc_proto_4 = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
};

static struct handshake_proto handshake_req_alloc_proto_5 = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
	.hp_accept		= test_accept_func,
};

static struct handshake_proto handshake_req_alloc_proto_6 = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
	.hp_privsize		= UINT_MAX,
	.hp_accept		= test_accept_func,
	.hp_done		= test_done_func,
};

static struct handshake_proto handshake_req_alloc_proto_good = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
	.hp_accept		= test_accept_func,
	.hp_done		= test_done_func,
};

static const
struct handshake_req_alloc_test_param handshake_req_alloc_params[] = {
	{
		.desc			= "handshake_req_alloc NULL proto",
		.proto			= NULL,
		.gfp			= GFP_KERNEL,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc CLASS_NONE",
		.proto			= &handshake_req_alloc_proto_2,
		.gfp			= GFP_KERNEL,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc CLASS_MAX",
		.proto			= &handshake_req_alloc_proto_3,
		.gfp			= GFP_KERNEL,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc no callbacks",
		.proto			= &handshake_req_alloc_proto_4,
		.gfp			= GFP_KERNEL,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc no done callback",
		.proto			= &handshake_req_alloc_proto_5,
		.gfp			= GFP_KERNEL,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc excessive privsize",
		.proto			= &handshake_req_alloc_proto_6,
		.gfp			= GFP_KERNEL | __GFP_NOWARN,
		.expect_success		= false,
	},
	{
		.desc			= "handshake_req_alloc all good",
		.proto			= &handshake_req_alloc_proto_good,
		.gfp			= GFP_KERNEL,
		.expect_success		= true,
	},
};

static void
handshake_req_alloc_get_desc(const struct handshake_req_alloc_test_param *param,
			     char *desc)
{
	strscpy(desc, param->desc, KUNIT_PARAM_DESC_SIZE);
}

/* Creates the function handshake_req_alloc_gen_params */
KUNIT_ARRAY_PARAM(handshake_req_alloc, handshake_req_alloc_params,
		  handshake_req_alloc_get_desc);

static void handshake_req_alloc_case(struct kunit *test)
{
	const struct handshake_req_alloc_test_param *param = test->param_value;
	struct handshake_req *result;

	/* Arrange */

	/* Act */
	result = handshake_req_alloc(param->proto, param->gfp);

	/* Assert */
	if (param->expect_success)
		KUNIT_EXPECT_NOT_NULL(test, result);
	else
		KUNIT_EXPECT_NULL(test, result);

	kfree(result);
}

static void handshake_req_submit_test1(struct kunit *test)
{
	struct socket *sock;
	int err, result;

	/* Arrange */
	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	/* Act */
	result = handshake_req_submit(sock, NULL, GFP_KERNEL);

	/* Assert */
	KUNIT_EXPECT_EQ(test, result, -EINVAL);

	sock_release(sock);
}

static void handshake_req_submit_test2(struct kunit *test)
{
	struct handshake_req *req;
	int result;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	/* Act */
	result = handshake_req_submit(NULL, req, GFP_KERNEL);

	/* Assert */
	KUNIT_EXPECT_EQ(test, result, -EINVAL);

	/* handshake_req_submit() destroys @req on error */
}

static void handshake_req_submit_test3(struct kunit *test)
{
	struct handshake_req *req;
	struct socket *sock;
	int err, result;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);
	sock->file = NULL;

	/* Act */
	result = handshake_req_submit(sock, req, GFP_KERNEL);

	/* Assert */
	KUNIT_EXPECT_EQ(test, result, -EINVAL);

	/* handshake_req_submit() destroys @req on error */
	sock_release(sock);
}

static void handshake_req_submit_test4(struct kunit *test)
{
	struct handshake_req *req, *result;
	unsigned long fcount_before;
	struct socket *sock;
	struct file *filp;
	int err;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);
	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	KUNIT_ASSERT_NOT_NULL(test, sock->sk);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	/* Act */
	result = handshake_req_hash_lookup(sock->sk);

	/* Assert */
	KUNIT_EXPECT_NOT_NULL(test, result);
	KUNIT_EXPECT_PTR_EQ(test, req, result);

	handshake_req_cancel(sock->sk);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);
	fput(filp);
}

static void handshake_req_submit_test5(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req;
	struct handshake_net *hn;
	struct socket *sock;
	struct file *filp;
	struct net *net;
	int saved, err;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);
	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	KUNIT_ASSERT_NOT_NULL(test, sock->sk);
	sock->file = filp;

	net = sock_net(sock->sk);
	hn = handshake_pernet(net);
	KUNIT_ASSERT_NOT_NULL(test, hn);

	saved = hn->hn_pending;
	hn->hn_pending = hn->hn_pending_max + 1;
	fcount_before = file_count(filp);

	/* Act */
	err = handshake_req_submit(sock, req, GFP_KERNEL);

	/* Assert */
	KUNIT_EXPECT_EQ(test, err, -EAGAIN);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	fput(filp);
	hn->hn_pending = saved;
}

static void handshake_req_submit_test6(struct kunit *test)
{
	struct handshake_req *req1, *req2;
	unsigned long fcount_before;
	struct socket *sock;
	struct file *filp;
	int err;

	/* Arrange */
	req1 = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req1);
	req2 = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req2);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);
	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	KUNIT_ASSERT_NOT_NULL(test, sock->sk);
	sock->file = filp;
	fcount_before = file_count(filp);

	/* Act */
	err = handshake_req_submit(sock, req1, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);
	err = handshake_req_submit(sock, req2, GFP_KERNEL);

	/* Assert */
	KUNIT_EXPECT_EQ(test, err, -EBUSY);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	handshake_req_cancel(sock->sk);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);
	fput(filp);
}

static void handshake_req_cancel_test1(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req;
	struct socket *sock;
	struct file *filp;
	bool result;
	int err;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	/* NB: handshake_req hasn't been accepted */

	/* Act */
	result = handshake_req_cancel(sock->sk);

	/* Assert */
	KUNIT_EXPECT_TRUE(test, result);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	fput(filp);
}

static void handshake_req_cancel_test2(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req, *next;
	struct handshake_net *hn;
	struct socket *sock;
	struct file *filp;
	struct net *net;
	bool result;
	int err;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	net = sock_net(sock->sk);
	hn = handshake_pernet(net);
	KUNIT_ASSERT_NOT_NULL(test, hn);

	/* Pretend to accept this request */
	next = handshake_req_next(hn, HANDSHAKE_HANDLER_CLASS_TLSHD);
	KUNIT_ASSERT_PTR_EQ(test, req, next);
	/* Simulate FD_PREPARE() consuming the file reference handed
	 * off by handshake_req_next(); see handshake_nl_accept_doit().
	 */
	fput(filp);

	/* Act */
	result = handshake_req_cancel(sock->sk);

	/* Assert */
	KUNIT_EXPECT_TRUE(test, result);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	fput(filp);
}

static void handshake_req_cancel_test3(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req, *next;
	struct handshake_net *hn;
	struct socket *sock;
	struct file *filp;
	struct net *net;
	bool result;
	int err;

	/* Arrange */
	req = handshake_req_alloc(&handshake_req_alloc_proto_good, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	net = sock_net(sock->sk);
	hn = handshake_pernet(net);
	KUNIT_ASSERT_NOT_NULL(test, hn);

	/* Pretend to accept this request */
	next = handshake_req_next(hn, HANDSHAKE_HANDLER_CLASS_TLSHD);
	KUNIT_ASSERT_PTR_EQ(test, req, next);
	/* Simulate FD_PREPARE() consuming the file reference handed
	 * off by handshake_req_next(); see handshake_nl_accept_doit().
	 */
	fput(filp);

	/* Pretend to complete this request */
	handshake_complete(next, -ETIMEDOUT, NULL);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	/* Act */
	result = handshake_req_cancel(sock->sk);

	/* Assert */
	KUNIT_EXPECT_FALSE(test, result);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	fput(filp);
}

static int handshake_try_complete_done_count;

static void test_done_count_func(struct handshake_req *req, int status,
				 struct genl_info *info)
{
	handshake_try_complete_done_count++;
}

static struct handshake_proto handshake_req_alloc_proto_count = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
	.hp_accept		= test_accept_func,
	.hp_done		= test_done_count_func,
};

static void handshake_try_complete_test1(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req, *next;
	struct handshake_net *hn;
	struct socket *sock;
	struct file *filp;
	struct net *net;
	bool first, second;
	int err;

	/* Arrange */
	handshake_try_complete_done_count = 0;

	req = handshake_req_alloc(&handshake_req_alloc_proto_count, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	KUNIT_ASSERT_NOT_NULL(test, sock->sk);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before + 1);

	net = sock_net(sock->sk);
	hn = handshake_pernet(net);
	KUNIT_ASSERT_NOT_NULL(test, hn);

	/* Pretend to accept this request */
	next = handshake_req_next(hn, HANDSHAKE_HANDLER_CLASS_TLSHD);
	KUNIT_ASSERT_PTR_EQ(test, req, next);
	/* Simulate FD_PREPARE() consuming the file reference handed
	 * off by handshake_req_next(); see handshake_nl_accept_doit().
	 */
	fput(filp);

	/* Act */
	first = handshake_try_complete(req);
	second = handshake_try_complete(req);
	handshake_finish_complete(req, 0, NULL, NULL);
	/* handshake_finish_complete() drops the request's pin on the file. */
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);
	/* handshake_complete() re-enters the gate via
	 * handshake_try_complete(). With the gate already taken,
	 * hp_done must not fire a second time.
	 */
	handshake_complete(req, 0, NULL);

	/* Assert */
	KUNIT_EXPECT_TRUE(test, first);
	KUNIT_EXPECT_FALSE(test, second);
	KUNIT_EXPECT_EQ(test, handshake_try_complete_done_count, 1);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	fput(filp);
}

static struct handshake_req *handshake_req_destroy_test;

static void test_destroy_func(struct handshake_req *req)
{
	handshake_req_destroy_test = req;
}

static struct handshake_proto handshake_req_alloc_proto_destroy = {
	.hp_handler_class	= HANDSHAKE_HANDLER_CLASS_TLSHD,
	.hp_accept		= test_accept_func,
	.hp_done		= test_done_func,
	.hp_destroy		= test_destroy_func,
};

static void handshake_req_destroy_test1(struct kunit *test)
{
	unsigned long fcount_before;
	struct handshake_req *req;
	struct socket *sock;
	struct file *filp;
	int err;

	/* Arrange */
	handshake_req_destroy_test = NULL;

	req = handshake_req_alloc(&handshake_req_alloc_proto_destroy, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	err = __sock_create(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &sock, 1);
	KUNIT_ASSERT_EQ(test, err, 0);

	filp = sock_alloc_file(sock, O_NONBLOCK, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, filp);
	sock->file = filp;

	fcount_before = file_count(filp);
	err = handshake_req_submit(sock, req, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, err, 0);

	handshake_req_cancel(sock->sk);
	KUNIT_EXPECT_EQ(test, file_count(filp), fcount_before);

	/* Act */
	/* Ensure the close/release/put process has run to
	 * completion before checking the result.
	 */
	__fput_sync(filp);

	/* Assert */
	KUNIT_EXPECT_PTR_EQ(test, handshake_req_destroy_test, req);
}

static struct sk_buff *handshake_done_msg(struct kunit *test,
					  struct nlmsghdr **nlhp)
{
	struct sk_buff *skb;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);
	*nlhp = nlmsg_put(skb, 0, 0, HANDSHAKE_CMD_DONE, GENL_HDRLEN, 0);
	KUNIT_ASSERT_NOT_NULL(test, *nlhp);
	return skb;
}

/*
 * handshake_get_sessiontags() leaves the collected set unfinalized,
 * as the netlink handler does. Cases below that query membership
 * finalize first, the way handshake_finish_complete() does before
 * delivery to the consumer.
 */
static void handshake_sessiontags_basic(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	skb = handshake_done_msg(test, &nlh);
	nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "alpha");
	nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "beta");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	stringset_finalize(&tags);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 2);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(&tags, "alpha"));
	KUNIT_EXPECT_TRUE(test, stringset_is_member(&tags, "beta"));

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_none(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	skb = handshake_done_msg(test, &nlh);
	nla_put_u32(skb, HANDSHAKE_A_DONE_STATUS, 0);
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 0);

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_trailing_nul(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	/* A payload of 6 carries "gamma" plus its terminator. */
	skb = handshake_done_msg(test, &nlh);
	nla_put(skb, HANDSHAKE_A_DONE_TAG, 6, "gamma");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	stringset_finalize(&tags);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 1);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(&tags, "gamma"));

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_embedded_nul(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	skb = handshake_done_msg(test, &nlh);
	nla_put(skb, HANDSHAKE_A_DONE_TAG, 3, "a\0b");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), -EINVAL);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 0);

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_empty(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	skb = handshake_done_msg(test, &nlh);
	nla_put(skb, HANDSHAKE_A_DONE_TAG, 0, "");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), -EINVAL);

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_duplicate(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);

	skb = handshake_done_msg(test, &nlh);
	nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "dup");
	nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "dup");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 1);
	stringset_finalize(&tags);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 1);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(&tags, "dup"));

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_duplicate_at_cap(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);
	unsigned int i;

	skb = handshake_done_msg(test, &nlh);
	for (i = 0; i < HANDSHAKE_MAX_SESSIONTAGS; i++)
		nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "dup");
	nla_put_string(skb, HANDSHAKE_A_DONE_TAG, "last");
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), 2);
	stringset_finalize(&tags);
	KUNIT_EXPECT_TRUE(test, stringset_is_member(&tags, "last"));

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static void handshake_sessiontags_truncate(struct kunit *test)
{
	struct genl_info info = {};
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	DEFINE_STRINGSET(tags);
	unsigned int i;

	skb = handshake_done_msg(test, &nlh);
	for (i = 0; i < HANDSHAKE_MAX_SESSIONTAGS + 6; i++) {
		char tag[16];

		snprintf(tag, sizeof(tag), "tag%u", i);
		nla_put_string(skb, HANDSHAKE_A_DONE_TAG, tag);
	}
	nlmsg_end(skb, nlh);
	info.nlhdr = nlh;

	KUNIT_EXPECT_EQ(test, handshake_get_sessiontags(&tags, &info), 0);
	KUNIT_EXPECT_EQ(test, stringset_count(&tags), HANDSHAKE_MAX_SESSIONTAGS);

	stringset_destroy(&tags);
	kfree_skb(skb);
}

static struct kunit_case handshake_api_test_cases[] = {
	{
		.name			= "req_alloc API fuzzing",
		.run_case		= handshake_req_alloc_case,
		.generate_params	= handshake_req_alloc_gen_params,
	},
	{
		.name			= "req_submit NULL req arg",
		.run_case		= handshake_req_submit_test1,
	},
	{
		.name			= "req_submit NULL sock arg",
		.run_case		= handshake_req_submit_test2,
	},
	{
		.name			= "req_submit NULL sock->file",
		.run_case		= handshake_req_submit_test3,
	},
	{
		.name			= "req_lookup works",
		.run_case		= handshake_req_submit_test4,
	},
	{
		.name			= "req_submit max pending",
		.run_case		= handshake_req_submit_test5,
	},
	{
		.name			= "req_submit multiple",
		.run_case		= handshake_req_submit_test6,
	},
	{
		.name			= "req_cancel before accept",
		.run_case		= handshake_req_cancel_test1,
	},
	{
		.name			= "req_cancel after accept",
		.run_case		= handshake_req_cancel_test2,
	},
	{
		.name			= "req_cancel after done",
		.run_case		= handshake_req_cancel_test3,
	},
	{
		.name			= "try_complete gate is exclusive",
		.run_case		= handshake_try_complete_test1,
	},
	{
		.name			= "req_destroy works",
		.run_case		= handshake_req_destroy_test1,
	},
	{
		.name			= "sessiontags basic",
		.run_case		= handshake_sessiontags_basic,
	},
	{
		.name			= "sessiontags none present",
		.run_case		= handshake_sessiontags_none,
	},
	{
		.name			= "sessiontags trailing NUL",
		.run_case		= handshake_sessiontags_trailing_nul,
	},
	{
		.name			= "sessiontags embedded NUL",
		.run_case		= handshake_sessiontags_embedded_nul,
	},
	{
		.name			= "sessiontags empty tag",
		.run_case		= handshake_sessiontags_empty,
	},
	{
		.name			= "sessiontags duplicate",
		.run_case		= handshake_sessiontags_duplicate,
	},
	{
		.name			= "sessiontags duplicates at cap",
		.run_case		= handshake_sessiontags_duplicate_at_cap,
	},
	{
		.name			= "sessiontags truncate at cap",
		.run_case		= handshake_sessiontags_truncate,
	},
	{}
};

static struct kunit_suite handshake_api_suite = {
       .name                   = "Handshake API tests",
       .test_cases             = handshake_api_test_cases,
};

kunit_test_suites(&handshake_api_suite);

MODULE_DESCRIPTION("Test handshake upcall API functions");
MODULE_LICENSE("GPL");
