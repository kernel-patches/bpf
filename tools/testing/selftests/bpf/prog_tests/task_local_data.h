#ifndef __BPF_TASK_LOCAL_DATA_H__
#define __BPF_TASK_LOCAL_DATA_H__

#include "task_local_data_common.h"

#define SEC(name) __attribute__((section(name), used))
#define __aligned(x) __attribute__((aligned(x)))

#define ROUND_UP_POWER_OF_TWO(x) (1UL << (sizeof(x) * 8 - __builtin_clzl(x - 1)))

void __bpf_tld_var_init(const char *key, void *var, int size);

/**
 * @brief bpf_tld_key_type_var() declares a task local data shared with bpf
 * programs. The data will be a thread-specific variable which a user space
 * program can directly read/write, while bpf programs will need to lookup
 * with the string key.
 *
 * @param key The string key a task local data will be associated with. The
 * string will be truncated if the length exceeds TASK_LOCAL_DATA_KEY_LEN
 * @param type The type of the task local data
 * @param var The name of the task local data
 */
#define bpf_tld_key_type_var(key, type, var)					\
__thread type var SEC("udata") __aligned(ROUND_UP_POWER_OF_TWO(sizeof(type)));	\
										\
__attribute__((constructor))							\
void __bpf_tld_##var##_init(void)						\
{										\
	_Static_assert(sizeof(type) < PAGE_SIZE,				\
		       "data size must not exceed a page");			\
	__bpf_tld_var_init(key, &var, sizeof(type));				\
}

/**
 * @brief bpf_tld_key_type_var() declares a task local data shared with bpf
 * programs. The data will be a thread-specific variable which a user space
 * program can directly read/write, while bpf programs will need to lookup
 * the data with the string key same as the variable name.
 *
 * @param type The type of the task local data
 * @param var The name of the task local data as well as the name of the
 * key. The key string will be truncated if the length exceeds
 * TASK_LOCAL_DATA_KEY_LEN.
 */
#define bpf_tld_type_var(type, var) \
	bpf_tld_key_type_var(#var, type, var)

/**
 * @brief bpf_tld_thread_init() initializes the task local data for the current
 * thread. All data are undefined from a bpf program's point of view until
 * bpf_tld_thread_init() is called.
 *
 * @return 0 on success; negative error number on failure
 */
int bpf_tld_thread_init(void);

#endif
