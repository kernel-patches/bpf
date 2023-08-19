// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>

typedef int bool;
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

int page_size = 0; /* userspace should set it */

int skip_sleepable = 0;
int skip_nonsleepable = 0;

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#define SOL_CUSTOM			0xdeadbeef

struct sockopt_sk {
	__u8 val;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct sockopt_sk);
} socket_storage_map SEC(".maps");

SEC("cgroup/getsockopt")
int _getsockopt(struct bpf_sockopt *ctx)
{
	__u8 *optval_end = ctx->optval_end;
	__u8 *optval = ctx->optval;
	struct sockopt_sk *storage;
	struct bpf_sock *sk;

	if (skip_nonsleepable)
		return 1;

	/* Bypass AF_NETLINK. */
	sk = ctx->sk;
	if (sk && sk->family == AF_NETLINK)
		goto out;

	/* Make sure bpf_get_netns_cookie is callable.
	 */
	if (bpf_get_netns_cookie(NULL) == 0)
		return 0;

	if (bpf_get_netns_cookie(ctx) == 0)
		return 0;

	if (ctx->level == SOL_IP && ctx->optname == IP_TOS) {
		/* Not interested in SOL_IP:IP_TOS;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		goto out;
	}

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_SNDBUF) {
		/* Not interested in SOL_SOCKET:SO_SNDBUF;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		goto out;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION) {
		/* Not interested in SOL_TCP:TCP_CONGESTION;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		goto out;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_ZEROCOPY_RECEIVE) {
		/* Verify that TCP_ZEROCOPY_RECEIVE triggers.
		 * It has a custom implementation for performance
		 * reasons.
		 */

		/* Check that optval contains address (__u64) */
		if (optval + sizeof(__u64) > optval_end)
			return 0; /* bounds check */

		if (((struct tcp_zerocopy_receive *)optval)->address != 0)
			return 0; /* unexpected data */

		goto out;
	}

	if (ctx->level == SOL_IP && ctx->optname == IP_FREEBIND) {
		if (optval + 1 > optval_end)
			return 0; /* bounds check */

		ctx->retval = 0; /* Reset system call return value to zero */

		/* Always export 0x55 */
		optval[0] = 0x55;
		ctx->optlen = 1;

		/* Userspace buffer is PAGE_SIZE * 2, but BPF
		 * program can only see the first PAGE_SIZE
		 * bytes of data.
		 */
		if (optval_end - optval != page_size)
			return 0; /* unexpected data size */

		return 1;
	}

	if (ctx->level != SOL_CUSTOM)
		return 0; /* deny everything except custom level */

	if (optval + 1 > optval_end)
		return 0; /* bounds check */

	storage = bpf_sk_storage_get(&socket_storage_map, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0; /* couldn't get sk storage */

	if (!ctx->retval)
		return 0; /* kernel should not have handled
			   * SOL_CUSTOM, something is wrong!
			   */
	ctx->retval = 0; /* Reset system call return value to zero */

	optval[0] = storage->val;
	ctx->optlen = 1;

	return 1;

out:
	/* optval larger than PAGE_SIZE use kernel's buffer. */
	if (ctx->optlen > page_size)
		ctx->optlen = 0;
	return 1;
}

SEC("cgroup/getsockopt.s")
int _getsockopt_s(struct bpf_sockopt *ctx)
{
	struct tcp_zerocopy_receive zcvr;
	struct bpf_dynptr optval_dynptr;
	struct sockopt_sk *storage;
	__u8 *optval, *optval_end;
	struct bpf_sock *sk;
	char buf[1];
	__u64 addr;
	int ret;

	if (skip_sleepable)
		return 1;

	/* Bypass AF_NETLINK. */
	sk = ctx->sk;
	if (sk && sk->family == AF_NETLINK)
		return 1;

	optval = ctx->optval;
	optval_end = ctx->optval_end;

	/* Make sure bpf_get_netns_cookie is callable.
	 */
	if (bpf_get_netns_cookie(NULL) == 0)
		return 0;

	if (bpf_get_netns_cookie(ctx) == 0)
		return 0;

	if (ctx->level == SOL_IP && ctx->optname == IP_TOS) {
		/* Not interested in SOL_IP:IP_TOS;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		return 1;
	}

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_SNDBUF) {
		/* Not interested in SOL_SOCKET:SO_SNDBUF;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		return 1;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION) {
		/* Not interested in SOL_TCP:TCP_CONGESTION;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		return 1;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_ZEROCOPY_RECEIVE) {
		/* Verify that TCP_ZEROCOPY_RECEIVE triggers.
		 * It has a custom implementation for performance
		 * reasons.
		 */

		bpf_dynptr_from_sockopt(ctx, &optval_dynptr);
		ret = bpf_dynptr_read(&zcvr, sizeof(zcvr),
				      &optval_dynptr, 0, 0);
		addr = ret >= 0 ? zcvr.address : 0;
		bpf_sockopt_dynptr_release(ctx, &optval_dynptr);

		return addr != 0 ? 0 : 1;
	}

	if (ctx->level == SOL_IP && ctx->optname == IP_FREEBIND) {
		if (optval + 1 > optval_end)
			return 0; /* bounds check */

		ctx->retval = 0; /* Reset system call return value to zero */

		/* Always export 0x55 */
		buf[0] = 0x55;
		ret = bpf_dynptr_from_sockopt(ctx, &optval_dynptr);
		if (ret >= 0) {
			bpf_dynptr_write(&optval_dynptr, 0, buf, 1, 0);
		}
		bpf_sockopt_dynptr_release(ctx, &optval_dynptr);
		if (ret < 0)
			return 0;
		ctx->optlen = 1;

		/* Userspace buffer is PAGE_SIZE * 2, but BPF
		 * program can only see the first PAGE_SIZE
		 * bytes of data.
		 */
		if (optval_end - optval != page_size && 0)
			return 0; /* unexpected data size */

		return 1;
	}

	if (ctx->level != SOL_CUSTOM)
		return 0; /* deny everything except custom level */

	if (optval + 1 > optval_end)
		return 0; /* bounds check */

	storage = bpf_sk_storage_get(&socket_storage_map, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0; /* couldn't get sk storage */

	if (!ctx->retval)
		return 0; /* kernel should not have handled
			   * SOL_CUSTOM, something is wrong!
			   */
	ctx->retval = 0; /* Reset system call return value to zero */

	buf[0] = storage->val;
	ret = bpf_dynptr_from_sockopt(ctx, &optval_dynptr);
	if (ret >= 0) {
		bpf_dynptr_write(&optval_dynptr, 0, buf, 1, 0);
	}
	bpf_sockopt_dynptr_release(ctx, &optval_dynptr);
	if (ret < 0)
		return 0;
	ctx->optlen = 1;

	return 1;
}

SEC("cgroup/setsockopt")
int _setsockopt(struct bpf_sockopt *ctx)
{
	__u8 *optval_end = ctx->optval_end;
	__u8 *optval = ctx->optval;
	struct sockopt_sk *storage;
	struct bpf_sock *sk;

	if (skip_nonsleepable)
		return 1;

	/* Bypass AF_NETLINK. */
	sk = ctx->sk;
	if (sk && sk->family == AF_NETLINK)
		goto out;

	/* Make sure bpf_get_netns_cookie is callable.
	 */
	if (bpf_get_netns_cookie(NULL) == 0)
		return 0;

	if (bpf_get_netns_cookie(ctx) == 0)
		return 0;

	if (ctx->level == SOL_IP && ctx->optname == IP_TOS) {
		/* Not interested in SOL_IP:IP_TOS;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		ctx->optlen = 0; /* bypass optval>PAGE_SIZE */
		return 1;
	}

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_SNDBUF) {
		/* Overwrite SO_SNDBUF value */

		if (optval + sizeof(__u32) > optval_end)
			return 0; /* bounds check */

		*(__u32 *)optval = 0x55AA;
		ctx->optlen = 4;

		return 1;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION) {
		/* Always use cubic */

		if (optval + 5 > optval_end)
			return 0; /* bounds check */

		memcpy(optval, "cubic", 5);
		ctx->optlen = 5;

		return 1;
	}

	if (ctx->level == SOL_IP && ctx->optname == IP_FREEBIND) {
		/* Original optlen is larger than PAGE_SIZE. */
		if (ctx->optlen != page_size * 2)
			return 0; /* unexpected data size */

		if (optval + 1 > optval_end)
			return 0; /* bounds check */

		/* Make sure we can trim the buffer. */
		optval[0] = 0;
		ctx->optlen = 1;

		/* Usepace buffer is PAGE_SIZE * 2, but BPF
		 * program can only see the first PAGE_SIZE
		 * bytes of data.
		 */
		if (optval_end - optval != page_size)
			return 0; /* unexpected data size */

		return 1;
	}

	if (ctx->level != SOL_CUSTOM)
		return 0; /* deny everything except custom level */

	if (optval + 1 > optval_end)
		return 0; /* bounds check */

	storage = bpf_sk_storage_get(&socket_storage_map, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0; /* couldn't get sk storage */

	storage->val = optval[0];
	ctx->optlen = -1; /* BPF has consumed this option, don't call kernel
			   * setsockopt handler.
			   */

	return 1;

out:
	/* optval larger than PAGE_SIZE use kernel's buffer. */
	if (ctx->optlen > page_size)
		ctx->optlen = 0;
	return 1;
}

SEC("cgroup/setsockopt.s")
int _setsockopt_s(struct bpf_sockopt *ctx)
{
	struct bpf_dynptr optval_buf;
	struct sockopt_sk *storage;
	__u8 *optval, *optval_end;
	struct bpf_sock *sk;
	__u8 tmp_u8;
	__u32 tmp;
	int ret;

	if (skip_sleepable)
		return 1;

	optval = ctx->optval;
	optval_end = ctx->optval_end;

	/* Bypass AF_NETLINK. */
	sk = ctx->sk;
	if (sk && sk->family == AF_NETLINK)
		return -1;

	/* Make sure bpf_get_netns_cookie is callable.
	 */
	if (bpf_get_netns_cookie(NULL) == 0)
		return 0;

	if (bpf_get_netns_cookie(ctx) == 0)
		return 0;

	if (ctx->level == SOL_IP && ctx->optname == IP_TOS) {
		/* Not interested in SOL_IP:IP_TOS;
		 * let next BPF program in the cgroup chain or kernel
		 * handle it.
		 */
		ctx->optlen = 0; /* bypass optval>PAGE_SIZE */
		return 1;
	}

	if (ctx->level == SOL_SOCKET && ctx->optname == SO_SNDBUF) {
		/* Overwrite SO_SNDBUF value */

		ret = bpf_dynptr_from_sockopt(ctx, &optval_buf);
		if (ret >= 0) {
			tmp = 0x55AA;
			bpf_dynptr_write(&optval_buf, 0, &tmp, sizeof(tmp), 0);
		}
		bpf_sockopt_dynptr_release(ctx, &optval_buf);

		return ret >= 0 ? 1 : 0;
	}

	if (ctx->level == SOL_TCP && ctx->optname == TCP_CONGESTION) {
		/* Always use cubic */

		if (optval + 5 > optval_end)
			bpf_sockopt_grow_to(ctx, 5);
		ret = bpf_dynptr_from_sockopt(ctx, &optval_buf);
		if (ret < 0) {
			bpf_sockopt_dynptr_release(ctx, &optval_buf);
			return 0;
		}
		bpf_dynptr_write(&optval_buf, 0, "cubic", 5, 0);
		bpf_sockopt_dynptr_release(ctx, &optval_buf);
		if (ret < 0)
			return 0;
		ctx->optlen = 5;

		return 1;
	}

	if (ctx->level == SOL_IP && ctx->optname == IP_FREEBIND) {
		/* Original optlen is larger than PAGE_SIZE. */
		if (ctx->optlen != page_size * 2)
			return 0; /* unexpected data size */

		ret = bpf_dynptr_from_sockopt(ctx, &optval_buf);
		if (ret < 0) {
			bpf_sockopt_dynptr_release(ctx, &optval_buf);
			return 0;
		}
		tmp_u8 = 0;
		bpf_dynptr_write(&optval_buf, 0, &tmp_u8, 1, 0);
		bpf_sockopt_dynptr_release(ctx, &optval_buf);
		if (ret < 0)
			return 0;
		ctx->optlen = 1;

		return 1;
	}

	if (ctx->level != SOL_CUSTOM)
		return 0; /* deny everything except custom level */

	if (optval + 1 > optval_end)
		return 0; /* bounds check */

	storage = bpf_sk_storage_get(&socket_storage_map, ctx->sk, 0,
				     BPF_SK_STORAGE_GET_F_CREATE);
	if (!storage)
		return 0; /* couldn't get sk storage */

	bpf_dynptr_from_sockopt(ctx, &optval_buf);
	ret = bpf_dynptr_read(&storage->val, sizeof(__u8), &optval_buf, 0, 0);
	if (ret >= 0) {
		ctx->optlen = -1; /* BPF has consumed this option, don't call
				   * kernel setsockopt handler.
				   */
	}
	bpf_sockopt_dynptr_release(ctx, &optval_buf);

	return optval ? 1 : 0;
}

