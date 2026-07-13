#include "constants.h"

static __always_inline struct task_struct *current_task() {
    if (lightswitch_config.use_task_pt_regs_helper && lightswitch_config.use_btf_helpers) {
        return bpf_get_current_task_btf();
    } else {
        return (struct task_struct *)bpf_get_current_task();
    }
}

static __always_inline struct pt_regs *pt_regs(struct task_struct *task) {
    if (lightswitch_config.use_task_pt_regs_helper && lightswitch_config.use_btf_helpers) {
        if (task == NULL) {
            return NULL;
        }
        return (struct pt_regs *)bpf_task_pt_regs(task);
    } else {
        if (task == NULL) {
            return NULL;
        }
        void *stack;
        int err = bpf_probe_read_kernel(&stack, 8, &task->stack);
        if (err) {
            LOG("[warn] bpf_probe_read_kernel failed with %d", err);
            return NULL;
        }
        void *ptr = stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
        return ((struct pt_regs *)ptr) - 1;
    }
}

static __always_inline mapping_t *find_mapping(int per_process_id, u64 pc) {
    struct exec_mappings_key key = {};
    key.prefix_len = PREFIX_LEN;
    key.pid = __builtin_bswap32((u32)per_process_id);
    key.data = __builtin_bswap64(pc);

    return bpf_map_lookup_elem(&exec_mappings, &key);
}

static __always_inline bool process_is_known(int per_process_id) {
    struct exec_mappings_key key = {};
    key.prefix_len = PREFIX_LEN;
    key.pid = __builtin_bswap32((u32)per_process_id);
    key.data = 0;

    return bpf_map_lookup_elem(&exec_mappings, &key) != NULL;
}
