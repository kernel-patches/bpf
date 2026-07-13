// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
// Copyright 2024 The Lightswitch Authors

#include "vmlinux.h"
#include "profiler.h"
#include "shared_maps.h"
#include "shared_helpers.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} stacks_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, unwind_state_t);
} heap SEC(".maps");

struct unwind_table_inner_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, UNWIND_INFO_PAGE_SIZE);
    __type(key, u32);
    __type(value, stack_unwind_row_t);
};

// Holds BPF array maps which store unwind information.

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_OUTER_UNWIND_MAP_ENTRIES);
    __type(key, u64);
    __type(value, u32);
    __array(values, struct unwind_table_inner_map);
} outer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_EXECUTABLE_TO_PAGE_ENTRIES);
    __type(key, page_key_t);
    __type(value, page_value_t);
} executable_to_page SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, u64);
    __type(value, bool);
} rate_limits SEC(".maps");

// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc) relative to the object file.
static __always_inline u64 find_offset_for_pc(void *inner_map, u16 pc_low, u64 left,
                                              u64 right) {
    u64 found = BINARY_SEARCH_DEFAULT;

// On kernels ~6.8 and greater the verifier fails with argument list too long. This did not use to
// happen before and it's probably due to a regression in the way the verifier accounts for the explored
// paths. I have tried many other things, such as two mid variables but that did not do it.
// Perhaps unrolling the loop works is that the verifier doesn't have as many states to explore
// per iteration.
#pragma unroll
    for (int i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++) {
        // TODO(javierhonduco): ensure that this condition is right as we use
        // unsigned values...
        if (left >= right) {
            LOG("\t.done");
            return found;
        }

        u32 mid = (left + right) / 2;

        stack_unwind_row_t *row = bpf_map_lookup_elem(inner_map, &mid);
        if (row == NULL) {
            return BINARY_SEARCH_DEFAULT;
        }

        if (row->pc_low <= pc_low) {
            found = mid;
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return BINARY_SEARCH_EXHAUSTED_ITERATIONS;
}

// Finds the shard information for a given pid and program counter. Optionally,
// and offset can be passed that will be filled in with the mapping's load
// address.
static __always_inline void *
find_page(mapping_t *mapping, u64 object_relative_pc, u64 *low_index, u64 *high_index) {
    page_key_t page_key = {
        .executable_id = mapping->executable_id,
        .file_offset = object_relative_pc,
    };

    page_value_t *found_page = bpf_map_lookup_elem(&executable_to_page, &page_key);

    if (found_page != NULL) {
        void *inner_map = bpf_map_lookup_elem(&outer_map, &mapping->executable_id);
        if (inner_map != NULL) {
            *low_index = found_page->low_index;
            *high_index = found_page->high_index;
            return inner_map;
        }
    }

    LOG("[error] could not find page for executable_id: %llx at file_offset: %llx", mapping->executable_id, object_relative_pc);
    bump_unwind_error_page_not_found();
    return NULL;
}

static __always_inline void send_event(Event *event, struct bpf_perf_event_data *ctx) {
    u64 event_id = ((u64)event->pid << 32 | event->type);
    bool *is_rate_limited = bpf_map_lookup_elem(&rate_limits, &event_id);
    if (is_rate_limited != NULL && *is_rate_limited) {
        LOG("[debug] send_event was rate limited for process %d", event->pid);
        return;
    }

    int ret = 0;
    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&events_rb, event, sizeof(Event), 0);
    } else {
        ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(Event));
    }
    if (ret < 0) {
        LOG("[error] failed to send event for process %d", event->pid);

        if (event->type == EVENT_NEW_PROCESS) {
            bump_unwind_error_sending_new_process_event();
        } else if (event->type == EVENT_NEED_UNWIND_INFO) {
            bump_unwind_error_sending_need_unwind_info_event();
        }
    }

    LOG("[debug] event type %d sent for process %d", event->type, event->pid);
    bool rate_limited = true;

    bpf_map_update_elem(&rate_limits, &event_id, &rate_limited, BPF_ANY);
}

// The return address points as the the instruction at which execution
// will resume after returning from a function call, we need to get the
// previous instruction's address.
static __always_inline u64 previous_instruction_addr(u64 addr) {
#ifdef __TARGET_ARCH_x86
    // On x86 it's not possible to find the previous instruction address
    // without fully disassembling the whole executable from the start.
    // By substracting 1 byte, we make sure to fall within the previous
    // instruction.
    return addr - 1;
#elif __TARGET_ARCH_arm64
    return addr - 4;
#endif
}

#ifdef __TARGET_ARCH_x86
static __always_inline u64 remove_pac(u64 addr) {
    return addr;
}
#elif __TARGET_ARCH_arm64
// Arm64 supports pointer authentication, we need to remove the signatured during
// unwinding.
static __always_inline u64 remove_pac(u64 addr) {
    // The signature is stored in the top 55 - virtual address size bits [0], which
    // is typically 48 bytes, hence we need to clear the top 7 bits. Clearing 8 bits
    // as they are all the non-addressable anyways.
    // - [0]: https://docs.kernel.org/arch/arm64/pointer-authentication.html#basic-support
    addr &= 0x0000FFFFFFFFFFFF;
    return addr;
}
#endif

// Kernel addresses have the top bits set.
static __always_inline bool in_kernel(u64 ip) { return ip & (1UL << 63); }

// kthreads mm's is not set.
//
// We don't check for the return value of `retrieve_task_registers`, it's
// caller due the verifier not liking that code.
static __always_inline bool is_kthread() {
    struct task_struct *task = current_task();
    if (task == NULL) {
        return false;
    }

    void *mm;
    int err = bpf_probe_read_kernel(&mm, 8, &task->mm);
    if (err) {
        LOG("[warn] bpf_probe_read_kernel failed with %d", err);
        return false;
    }

    return mm == NULL;
}

// avoid R0 invalid mem access 'scalar'
// Port of `task_pt_regs` in BPF.
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp, u64 *lr) {
    if (ip == NULL || sp == NULL || bp == NULL || lr == NULL) {
        return false;
    }

    if (is_kthread()) {
        return false;
    }

    struct task_struct *task = current_task();
    struct pt_regs *regs = pt_regs(task);
    if (regs == NULL) {
        return false;
    }

    *ip = PT_REGS_IP_CORE(regs);
    *sp = PT_REGS_SP_CORE(regs);
    *bp = PT_REGS_FP_CORE(regs);
#ifdef __TARGET_ARCH_arm64
    *lr = PT_REGS_RET_CORE(regs);
#endif
    return true;
}

static __always_inline void add_stack(struct bpf_perf_event_data *ctx,
                                      unwind_state_t *unwind_state) {
    // Unwind and copy kernel stack.
    u32 ulen = unwind_state->sample.stack.ulen;
    if (ulen < MAX_STACK_DEPTH) {
        int ret = bpf_get_stack(ctx, &unwind_state->sample.stack.addresses[ulen], MAX_STACK_DEPTH * sizeof(u64), 0);
        if (ret > 0) {
            unwind_state->sample.stack.klen = ret / sizeof(u64);
        }
    }

    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
    int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

    unwind_state->sample.pid = per_process_id;
    unwind_state->sample.tid = per_thread_id;
    unwind_state->sample.collected_at = bpf_ktime_get_boot_ns();

    u32 sample_size = sizeof(sample_t)
                      // Remove the actual stack buffer which was doubled to appease the verifier.
                      - 2 * MAX_STACK_DEPTH * sizeof(u64)
                      // Add the actual stack size in bytes.
                      + (unwind_state->sample.stack.ulen + unwind_state->sample.stack.klen) * sizeof(u64);

    // Appease the verifier.
    if (sample_size > sizeof(sample_t)) {
        return;
    }

    int ret = 0;
    if (lightswitch_config.use_ring_buffers) {
        ret = bpf_ringbuf_output(&stacks_rb, &(unwind_state->sample), sample_size, 0);
    } else {
        ret = bpf_perf_event_output(ctx, &stacks, BPF_F_CURRENT_CPU, &(unwind_state->sample), sample_size);
    }

    if (ret < 0) {
        bpf_printk(
            "add_stack failed ret=%d, use_ring_buffers=%d",
            ret,
            lightswitch_config.use_ring_buffers);
        bump_unwind_error_failure_sending_stack();
    }
}

// The unwinding machinery lives here.
SEC("perf_event")
int dwarf_unwind(struct bpf_perf_event_data *ctx) {
    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    bool reached_bottom_of_stack = false;
    u64 zero = 0;

    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        LOG("unwind_state is NULL, should not happen");
        return 1;
    }

    for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
        // LOG("[debug] Within unwinding machinery loop");
        LOG("## frame: %d", unwind_state->sample.stack.ulen);
        LOG("\tcurrent pc: %llx", unwind_state->ip);
        LOG("\tcurrent sp: %llx", unwind_state->sp);
        LOG("\tcurrent bp: %llx", unwind_state->bp);

        mapping_t *mapping = find_mapping(per_process_id, unwind_state->ip);

        if (mapping == NULL) {
            LOG("[error] no mapping found for pc %llx", unwind_state->ip);
            bump_unwind_error_mapping_not_found();
            return 1;
        }

        if (unwind_state->ip < mapping->begin || unwind_state->ip >= mapping->end) {
            LOG("[error] pc %llx not contained within begin: %llx end: %llx", unwind_state->ip, mapping->begin, mapping->end);
            bump_unwind_error_mapping_does_not_contain_pc();
            return 1;
        }

        if (mapping->type == MAPPING_TYPE_ANON) {
            LOG("JIT section, stopping");
            bump_unwind_jit_encountered();
            return 1;
        }

        if (mapping->type == MAPPING_TYPE_VDSO) {
            LOG("vDSO section");
            bump_unwind_vdso_encountered();
        }

        u64 object_relative_pc = unwind_state->ip - mapping->load_address;
        u64 object_relative_pc_high = HIGH_PC(object_relative_pc);
        u16 object_relative_pc_low = LOW_PC(object_relative_pc);

        u64 low_index = 0;
        u64 high_index = 0;
        void *inner = find_page(mapping, object_relative_pc_high, &low_index, &high_index);
        if (inner == NULL) {
            Event event = {
                .type = EVENT_NEED_UNWIND_INFO,
                .pid = per_process_id,
                // Assume 4KB pages, hence the offset within the page does not offer any
                // additional information to find the right memory mapping. This way the
                // rate limiting logic will work better due to the reduced cardinality of
                // the rate limiting key.
                .address = unwind_state->ip & PAGE_MASK,
            };
            send_event(&event, ctx);
            return 1;
        }

        u64 table_idx = find_offset_for_pc(inner, object_relative_pc_low, low_index, high_index);

        if (table_idx == BINARY_SEARCH_DEFAULT ||
            table_idx == BINARY_SEARCH_SHOULD_NEVER_HAPPEN ||
            table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
            bool in_previous_page = false;

            if (table_idx == BINARY_SEARCH_DEFAULT) {
                low_index -= 1;
                stack_unwind_row_t *previous_row = bpf_map_lookup_elem(inner, &low_index);
                if (previous_row != NULL && object_relative_pc > PREVIOUS_PAGE(object_relative_pc_high) + previous_row->pc_low) {
                    table_idx = low_index;
                    in_previous_page = true;
                }
            }

            if (!in_previous_page) {
                LOG("[error] binary search failed with %llx, pc: %llx", table_idx, unwind_state->ip);
                if (table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
                    bump_unwind_error_binary_search_exhausted_iterations();
                }
                return 1;
            }
        }

        LOG("\t=> table_index: %d", table_idx);
        LOG("\t=> object relative pc: %llx", object_relative_pc);

        stack_unwind_row_t *row = bpf_map_lookup_elem(inner, &table_idx);
        if (row == NULL) {
            return 1;
        }

        u64 found_pc = object_relative_pc_high + row->pc_low;
        u8 found_cfa_type = row->cfa_type;
        u8 found_rbp_type = row->rbp_type;
        s16 found_cfa_offset = row->cfa_offset;
        s16 found_rbp_offset = row->rbp_offset;
        LOG("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type,
            found_cfa_offset, found_pc);

        if (found_cfa_type == CFA_TYPE_OFFSET_DID_NOT_FIT) {
            bump_unwind_error_cfa_offset_did_not_fit();
            return 1;
        }

        if (found_cfa_type == CFA_TYPE_END_OF_FDE_MARKER) {
            LOG("[info] pc %llx not contained in the unwind info, found marker",
                unwind_state->ip);
            reached_bottom_of_stack = true;
            break;
        }

        if (found_rbp_type == RBP_TYPE_OFFSET_DID_NOT_FIT) {
            bump_unwind_error_rbp_offset_did_not_fit();
            return 1;
        }

        if (found_rbp_type == RBP_TYPE_UNDEFINED_RETURN_ADDRESS) {
            LOG("[info] null return address, end of stack", unwind_state->ip);
            reached_bottom_of_stack = true;
            break;
        }

        // Add address to stack.
        u32 ulen = unwind_state->sample.stack.ulen;
        // Appease the verifier.
        if (ulen < MAX_STACK_DEPTH) {
            unwind_state->sample.stack.addresses[ulen] = unwind_state->ip;
            unwind_state->sample.stack.ulen++;
        }

        if (found_rbp_type == RBP_TYPE_REGISTER ||
            found_rbp_type == RBP_TYPE_EXPRESSION) {
            LOG("\t[error] frame pointer is %d (register or exp), bailing out",
                found_rbp_type);
            bump_unwind_error_unsupported_frame_pointer_action();
            return 1;
        }

        u64 previous_rsp = 0;
        if (found_cfa_type == CFA_TYPE_RBP) {
            previous_rsp = unwind_state->bp + found_cfa_offset;
        } else if (found_cfa_type == CFA_TYPE_RSP) {
            previous_rsp = unwind_state->sp + found_cfa_offset;
        } else if (found_cfa_type == CFA_TYPE_DEREF_AND_ADD) {
            u8 offset = found_cfa_offset >> 8;
            u8 addition = found_cfa_offset;
            LOG("dwarf exp: *($rsp + %d) + %d", offset, addition);
            int ret =
                bpf_probe_read_user(&previous_rsp, 8, (void *)(unwind_state->sp + offset));
            if (ret < 0) {
                LOG("[error] reading previous rsp failed with %d", ret);
                bump_unwind_error_previous_rsp_read();
            }
            previous_rsp += addition;
        } else if (found_cfa_type == CFA_TYPE_CFA_TYPE_UNSUP_EXP) {
            bump_unwind_error_unsupported_expression();
            return 1;
        } else if (found_cfa_type == CFA_TYPE_PLT1 || found_cfa_type == CFA_TYPE_PLT2) {
            LOG("CFA expression found with id %d", found_cfa_offset);
            u64 threshold = found_cfa_type == CFA_TYPE_PLT1 ? 11 : 10;

            if (threshold == 0) {
                bump_unwind_error_should_never_happen();
                return 1;
            }
            previous_rsp = unwind_state->sp + 8 +
                           ((((unwind_state->ip & 15) >= threshold)) << 3);
        } else {
            LOG("\t[unsup] cfa type %d not valid at ip: %llx", found_cfa_type, object_relative_pc);
            bump_unwind_error_unsupported_cfa_register();
            return 1;
        }

        // TODO(javierhonduco): A possible check could be to see whether this value
        // is within the stack. This check could be quite brittle though, so if we
        // add it, it would be best to add it only during development.
        if (previous_rsp == 0) {
            LOG("[error] previous_rsp should not be zero.");
            bump_unwind_error_previous_rsp_zero();
            return 1;
        }

        // Set rbp register.
        u64 previous_rbp = 0;
        u64 previous_rbp_addr = previous_rsp + found_rbp_offset;

        if (found_rbp_type == RBP_TYPE_UNCHANGED) {
            previous_rbp = unwind_state->bp;
        } else {
            LOG("\t(bp_offset: %d, bp value stored at %llx)", found_rbp_offset,
                previous_rbp_addr);
            int ret =
                bpf_probe_read_user(&previous_rbp, 8, (void *)(previous_rbp_addr));
            if (ret < 0) {
                LOG("[error] previous_rbp read failed with %d", ret);
                bump_unwind_error_previous_rbp_read();
                return 1;
            }
        }

        u64 previous_rip = 0;
        u64 previous_rip_addr = 0;
        int err = 0;

#ifdef __TARGET_ARCH_x86
        // The return address is guaranteed to be 8 bytes ahead of
        // the previous stack pointer in x86_64.
        previous_rip_addr = previous_rsp - 8;
        err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));

#endif

#ifdef __TARGET_ARCH_arm64
        // Special handling for leaf frame. Binaries with .eh_frame will have
        // a explicit usage of the LR register, while syntethised binaries do
        // not, such as Golang and Arm64 vDSO.
        if (found_rbp_type == RBP_TYPE_ARM64_RETURN_ADDRESS_LR) {
            previous_rip = unwind_state->lr;
        } else if (found_rbp_type == RBP_TYPE_ARM64_RETURN_ADDRESS_FRAME) {
            // The binary was compiled with frame pointers, the location of the return
            // address is guaranteed by the Aarch64 ABI.
            previous_rip_addr = previous_rbp_addr + 8;
            err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));
        } else {
            // If there are not frame pointers, we need to fetch the return address somewhere
            // else in the stack.
            previous_rip_addr = previous_rsp + found_rbp_offset;
            err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));
        }
#endif

        if (err < 0) {
            LOG("[error] previous_rip read failed, ret=%d @ %llx",
                err, previous_rip_addr);
            bump_unwind_error_previous_rip_read();
            return 1;
        }

        if (previous_rip == 0) {
            LOG("[error] previous_rip is zero, ret=%d @ %llx", err, previous_rip_addr);
            bump_unwind_error_previous_rip_zero();
            return 1;
        }

        LOG("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
        LOG("\tprevious sp: %llx", previous_rsp);
        // Set rsp and rip registers
        unwind_state->ip = previous_instruction_addr(remove_pac(previous_rip));
        unwind_state->sp = previous_rsp;
        // Set rbp
        LOG("\tprevious bp: %llx", previous_rbp);
        unwind_state->bp = previous_rbp;

        // Frame finished! :)
    }

    if (reached_bottom_of_stack) {
#ifdef __TARGET_ARCH_x86
        // We've reached the bottom of the stack once we don't find an unwind
        // entry for the given program counter and the current frame pointer
        // is 0. As per the x86_64 ABI:
        //
        // From 3.4.1 Initial Stack and Register State
        // > %rbp The content of this register is unspecified at process
        // > initialization time, but the user code should mark the deepest
        // > stack frame by setting the frame pointer to zero.
        //
        // Note: the initial register state only applies to processes not to threads.
        //
        // https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
        int per_thread_id = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
        bool main_thread = per_process_id == per_thread_id;
        if (main_thread && unwind_state->bp != 0) {
            LOG("[error] Expected rbp to be 0 on main thread but found %llx, pc: %llx", unwind_state->bp, unwind_state->ip);
            bump_unwind_bp_non_zero_for_bottom_frame();
        }
#endif
        LOG("======= reached bottom frame! =======");
        add_stack(ctx, unwind_state);
        bump_unwind_success_dwarf();
        return 0;

    } else if (unwind_state->sample.stack.ulen < MAX_STACK_DEPTH &&
               unwind_state->tail_calls < MAX_TAIL_CALLS) {
        LOG("Continuing walking the stack in a tail call, current tail %d",
            unwind_state->tail_calls);
        unwind_state->tail_calls++;
        bpf_tail_call(ctx, &programs, PROGRAM_NATIVE_UNWINDER);
    }

    // We couldn't get the whole stacktrace.
    LOG("Truncated stack, won't be sent");
    bump_unwind_error_truncated();
    return 0;
}

// Set up the initial unwinding state.
static __always_inline bool set_initial_state(unwind_state_t *unwind_state, bpf_user_pt_regs_t *regs) {
    unwind_state->sample.stack.ulen = 0;
    unwind_state->sample.stack.klen = 0;
    unwind_state->tail_calls = 0;

    unwind_state->sample.pid = 0;
    unwind_state->sample.tid = 0;
    unwind_state->sample.collected_at = 0;

    if (in_kernel(PT_REGS_IP(regs))) {
        if (!retrieve_task_registers(&unwind_state->ip, &unwind_state->sp, &unwind_state->bp, &unwind_state->lr)) {
            // in kernelspace, but failed, probs a kworker
            // todo: bump counter
            return false;
        }
    } else {
        // Currently executing userspace code.
        unwind_state->ip = PT_REGS_IP(regs);
        unwind_state->sp = PT_REGS_SP(regs);
        unwind_state->bp = PT_REGS_FP(regs);
        unwind_state->lr = remove_pac(PT_REGS_RET(regs));
    }

    return true;
}

SEC("perf_event")
int on_event(struct bpf_perf_event_data *ctx) {
    struct task_struct *task = current_task();
    unsigned int level = lightswitch_config.userspace_pid_ns_level;
    int per_process_id = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    // There's no point in checking for the swapper process.
    if (per_process_id == 0) {
        return 0;
    }

    // Discard kworkers.
    if (is_kthread()) {
        return 0;
    }

    if (process_is_known(per_process_id)) {
        bump_unwind_total();

        u32 zero = 0;
        unwind_state_t *profiler_state = bpf_map_lookup_elem(&heap, &zero);
        if (profiler_state == NULL) {
            LOG("[error] profiler state should never be NULL");
            return 0;
        }
        set_initial_state(profiler_state, &ctx->regs);

        bpf_tail_call(ctx, &programs, PROGRAM_NATIVE_UNWINDER);
        return 0;
    }

    Event event = {
        .type = EVENT_NEW_PROCESS,
        .pid = per_process_id,
    };
    // Send the main thread's name.
    BPF_CORE_READ_STR_INTO(&event.comm, task, group_leader, comm);
    send_event(&event, ctx);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
