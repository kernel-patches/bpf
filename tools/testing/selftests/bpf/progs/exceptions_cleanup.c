// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8);
} ringbuf SEC(".maps");

enum {
    RES_DYNPTR,
    RES_ITER,
    RES_REG,
    RES_SPILL,
    __RES_MAX,
};

struct bpf_resource {
    int type;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, struct bpf_resource);
} hashmap SEC(".maps");

const volatile bool always_false = false;
bool only_count = false;
int res_count = 0;

#define MARK_RESOURCE(ptr, type) ({ res_count++; bpf_map_update_elem(&hashmap, &(void *){ptr}, &(struct bpf_resource){type}, 0); });
#define FIND_RESOURCE(ptr) ((struct bpf_resource *)bpf_map_lookup_elem(&hashmap, &(void *){ptr}) ?: &(struct bpf_resource){__RES_MAX})
#define FREE_RESOURCE(ptr) bpf_map_delete_elem(&hashmap, &(void *){ptr})
#define VAL 0xeB9F

SEC("fentry/bpf_cleanup_resource")
int BPF_PROG(exception_cleanup_mark_free, struct bpf_frame_desc_reg_entry *fd, void *ptr)
{
    if (fd->spill_type == STACK_INVALID)
        bpf_probe_read_kernel(&ptr, sizeof(ptr), ptr);
    if (only_count) {
        res_count--;
        return 0;
    }
    switch (fd->spill_type) {
    case STACK_SPILL:
        if (FIND_RESOURCE(ptr)->type == RES_SPILL)
            FREE_RESOURCE(ptr);
        break;
    case STACK_INVALID:
        if (FIND_RESOURCE(ptr)->type == RES_REG)
            FREE_RESOURCE(ptr);
        break;
    case STACK_ITER:
        if (FIND_RESOURCE(ptr)->type == RES_ITER)
            FREE_RESOURCE(ptr);
        break;
    case STACK_DYNPTR:
        if (FIND_RESOURCE(ptr)->type == RES_DYNPTR)
            FREE_RESOURCE(ptr);
        break;
    }
    return 0;
}

static long map_cb(struct bpf_map *map, void *key, void *value, void *ctx)
{
    int *cnt = ctx;

    (*cnt)++;
    return 0;
}

SEC("tc")
int exceptions_cleanup_check(struct __sk_buff *ctx)
{
    int cnt = 0;

    if (only_count)
        return res_count;
    bpf_for_each_map_elem(&hashmap, map_cb, &cnt, 0);
    return cnt;
}

SEC("tc")
int exceptions_cleanup_prog_num_iter(struct __sk_buff *ctx)
{
    int i;

    bpf_for(i, 0, 10) {
        MARK_RESOURCE(&___it, RES_ITER);
        bpf_throw(VAL);
    }
    return 0;
}

SEC("tc")
int exceptions_cleanup_prog_num_iter_mult(struct __sk_buff *ctx)
{
    int i, j, k;

    bpf_for(i, 0, 10) {
        MARK_RESOURCE(&___it, RES_ITER);
        bpf_for(j, 0, 10) {
            MARK_RESOURCE(&___it, RES_ITER);
            bpf_for(k, 0, 10) {
                MARK_RESOURCE(&___it, RES_ITER);
                bpf_throw(VAL);
            }
        }
    }
    return 0;
}

__noinline
static int exceptions_cleanup_subprog(struct __sk_buff *ctx)
{
    int i;

    bpf_for(i, 0, 10) {
        MARK_RESOURCE(&___it, RES_ITER);
        bpf_throw(VAL);
    }
    return ctx->len;
}

SEC("tc")
int exceptions_cleanup_prog_dynptr_iter(struct __sk_buff *ctx)
{
    struct bpf_dynptr rbuf;
    int ret = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &rbuf);
    MARK_RESOURCE(&rbuf, RES_DYNPTR);
    if (ctx->protocol)
        ret = exceptions_cleanup_subprog(ctx);
    bpf_ringbuf_discard_dynptr(&rbuf, 0);
    return ret;
}

SEC("tc")
int exceptions_cleanup_obj(struct __sk_buff *ctx)
{
    struct { int i; } *p;

    p = bpf_obj_new(typeof(*p));
    MARK_RESOURCE(&p, RES_SPILL);
    bpf_throw(VAL);
    return p->i;
}

SEC("tc")
int exceptions_cleanup_percpu_obj(struct __sk_buff *ctx)
{
    struct { int i; } *p;

    p = bpf_percpu_obj_new(typeof(*p));
    MARK_RESOURCE(&p, RES_SPILL);
    bpf_throw(VAL);
    return !p;
}

SEC("tc")
int exceptions_cleanup_ringbuf(struct __sk_buff *ctx)
{
    void *p;

    p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    MARK_RESOURCE(&p, RES_SPILL);
    bpf_throw(VAL);
    return 0;
}

SEC("tc")
int exceptions_cleanup_reg(struct __sk_buff *ctx)
{
    void *p;

    p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    MARK_RESOURCE(p, RES_REG);
    bpf_throw(VAL);
    if (p)
        bpf_ringbuf_discard(p, 0);
    return 0;
}

SEC("tc")
int exceptions_cleanup_null_or_ptr_do_ptr(struct __sk_buff *ctx)
{
    union {
        void *p;
        char buf[8];
    } volatile p;
    u64 z = 0;

    __builtin_memcpy((void *)&p.p, &z, sizeof(z));
    MARK_RESOURCE((void *)&p.p, RES_SPILL);
    if (ctx->len)
        p.p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    bpf_throw(VAL);
    return 0;
}

SEC("tc")
int exceptions_cleanup_null_or_ptr_do_null(struct __sk_buff *ctx)
{
    union {
        void *p;
        char buf[8];
    } volatile p;

    p.p = 0;
    MARK_RESOURCE((void *)p.buf, RES_SPILL);
    if (!ctx->len)
        p.p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    bpf_throw(VAL);
    return 0;
}

__noinline static int mark_resource_subprog(u64 a, u64 b, u64 c, u64 d)
{
    MARK_RESOURCE((void *)a, RES_REG);
    MARK_RESOURCE((void *)b, RES_REG);
    MARK_RESOURCE((void *)c, RES_REG);
    MARK_RESOURCE((void *)d, RES_REG);
    return 0;
}

SEC("tc")
int exceptions_cleanup_callee_saved(struct __sk_buff *ctx)
{
    asm volatile (
       "r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        r6 = r0;                        \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        r7 = r0;                        \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        r8 = r0;                        \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        call %[bpf_ringbuf_reserve];    \
        r9 = r0;                        \
        r1 = r6;                        \
        r2 = r7;                        \
        r3 = r8;                        \
        r4 = r9;                        \
        call mark_resource_subprog;     \
        r1 = 0xeB9F;                    \
        call bpf_throw;                 \
    " : : __imm(bpf_ringbuf_reserve),
          __imm_addr(ringbuf)
      : __clobber_all);
    mark_resource_subprog(0, 0, 0, 0);
    return 0;
}

SEC("tc")
int exceptions_cleanup_callee_saved_noopt(struct __sk_buff *ctx)
{
    mark_resource_subprog(1, 2, 3, 4);
    return 0;
}

__noinline int global_subprog_throw(struct __sk_buff *ctx)
{
    u64 *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    bpf_throw(VAL);
    return p ? *p : 0 + ctx->len;
}

__noinline int global_subprog(struct __sk_buff *ctx)
{
    u64 *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    if (!p)
        return ctx->len;
    global_subprog_throw(ctx);
    bpf_ringbuf_discard(p, 0);
    return !!p + ctx->len;
}

__noinline static int static_subprog(struct __sk_buff *ctx)
{
    struct bpf_dynptr rbuf;
    u64 *p, r = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &rbuf);
    p = bpf_dynptr_data(&rbuf, 0, 8);
    if (!p)
        goto end;
    *p = global_subprog(ctx);
    r += *p;
end:
    bpf_ringbuf_discard_dynptr(&rbuf, 0);
    return r + ctx->len;
}

SEC("tc")
int exceptions_cleanup_frame(struct __sk_buff *ctx)
{
    struct foo { int i; } *p = bpf_obj_new(typeof(*p));
    int i;
    only_count = 1;
    res_count = 4;
    if (!p)
        return 1;
    p->i = static_subprog(ctx);
    i = p->i;
    bpf_obj_drop(p);
    return i + ctx->len;
}

SEC("tc")
__success
int exceptions_cleanup_loop_iterations(struct __sk_buff *ctx)
{
    struct { int i; } *f[50] = {};
    int i;

    only_count = true;

    for (i = 0; i < 50; i++) {
        f[i] = bpf_obj_new(typeof(*f[0]));
        if (!f[i])
            goto end;
        res_count++;
        if (i == 49) {
            bpf_throw(VAL);
        }
    }
end:
    for (i = 0; i < 50; i++) {
        if (!f[i])
            continue;
        bpf_obj_drop(f[i]);
    }
    return 0;
}

SEC("tc")
int exceptions_cleanup_dead_code_elim(struct __sk_buff *ctx)
{
    void *p;

    p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    if (!p)
        return 0;
    asm volatile (
        "r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
    " ::: "r0");
    bpf_throw(VAL);
    bpf_ringbuf_discard(p, 0);
    return 0;
}

__noinline int global_subprog_throw_dce(struct __sk_buff *ctx)
{
    u64 *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    bpf_throw(VAL);
    return p ? *p : 0 + ctx->len;
}

__noinline int global_subprog_dce(struct __sk_buff *ctx)
{
    u64 *p = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    if (!p)
        return ctx->len;
    asm volatile (
        "r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
    " ::: "r0");
    global_subprog_throw_dce(ctx);
    bpf_ringbuf_discard(p, 0);
    return !!p + ctx->len;
}

__noinline static int static_subprog_dce(struct __sk_buff *ctx)
{
    struct bpf_dynptr rbuf;
    u64 *p, r = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, &rbuf);
    p = bpf_dynptr_data(&rbuf, 0, 8);
    if (!p)
        goto end;
    asm volatile (
        "r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
         r0 = r0;        \
    " ::: "r0");
    *p = global_subprog_dce(ctx);
    r += *p;
end:
    bpf_ringbuf_discard_dynptr(&rbuf, 0);
    return r + ctx->len;
}

SEC("tc")
int exceptions_cleanup_frame_dce(struct __sk_buff *ctx)
{
    struct foo { int i; } *p = bpf_obj_new(typeof(*p));
    int i;
    only_count = 1;
    res_count = 4;
    if (!p)
        return 1;
    p->i = static_subprog_dce(ctx);
    i = p->i;
    bpf_obj_drop(p);
    return i + ctx->len;
}

SEC("tc")
int reject_slot_with_zero_vs_ptr_ok(struct __sk_buff *ctx)
{
    asm volatile (
       "r7 = *(u32 *)(r1 + 0);          \
        r0 = 0;                         \
        *(u64 *)(r10 - 8) = r0;         \
        r1 = %[ringbuf] ll;             \
        r2 = 8;                         \
        r3 = 0;                         \
        if r7 != 0 goto jump4;          \
        call %[bpf_ringbuf_reserve];    \
        *(u64 *)(r10 - 8) = r0;         \
    jump4:                              \
        r0 = 0;                         \
        r1 = 0;                         \
        call bpf_throw;                 \
    " : : __imm(bpf_ringbuf_reserve),
          __imm_addr(ringbuf)
      : "memory");
    return 0;
}

char _license[] SEC("license") = "GPL";
