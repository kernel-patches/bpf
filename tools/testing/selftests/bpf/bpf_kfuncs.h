#ifndef __BPF_KFUNCS__
#define __BPF_KFUNCS__

struct bpf_sock_addr_kern;

/* Description
 *  Initializes an skb-type dynptr
 * Returns
 *  Error code
 */
extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
    struct bpf_dynptr *ptr__uninit) __ksym;

/* Description
 *  Initializes an xdp-type dynptr
 * Returns
 *  Error code
 */
extern int bpf_dynptr_from_xdp(struct xdp_md *xdp, __u64 flags,
			       struct bpf_dynptr *ptr__uninit) __ksym;

/* Description
 *  Obtain a read-only pointer to the dynptr's data
 * Returns
 *  Either a direct pointer to the dynptr data or a pointer to the user-provided
 *  buffer if unable to obtain a direct pointer
 */
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
			      void *buffer, __u32 buffer__szk) __ksym;

/* Description
 *  Obtain a read-write pointer to the dynptr's data
 * Returns
 *  Either a direct pointer to the dynptr data or a pointer to the user-provided
 *  buffer if unable to obtain a direct pointer
 */
extern void *bpf_dynptr_slice_rdwr(const struct bpf_dynptr *ptr, __u32 offset,
			      void *buffer, __u32 buffer__szk) __ksym;

/* Description
 *  Modify the contents of a sockaddr.
 * Returns__bpf_kfunc
 *  -EINVAL if the sockaddr family does not match, the sockaddr is too small or
 *  too big, 0 if the sockaddr was successfully modified.
 */
extern int bpf_sock_addr_set(struct bpf_sock_addr_kern *sa_kern,
			     const void *addr, __u32 addrlen__sz) __ksym;

void *bpf_rdonly_cast(void *obj, __u32 btf_id) __ksym;

#endif
