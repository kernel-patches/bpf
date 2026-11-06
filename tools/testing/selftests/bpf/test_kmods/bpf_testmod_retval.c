// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for the fmod_ret targets which the LLVM IR scanner finds, see
 * prog_tests/fmodret_retval.c. The "test_retval:" decl tag of each lists the
 * values the scanner must find on paths without side effects. An empty list
 * means that the function must not become such a target.
 */
#include <linux/atomic.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/compiler.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/error-injection.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define RETVAL(values)	__attribute__((btf_decl_tag("test_retval:" values)))

static __used int bpf_testmod_retval_state;
static __used int *bpf_testmod_retval_captured;

static noinline void bpf_testmod_retval_effect(void)
{
	WRITE_ONCE(bpf_testmod_retval_state, 1);
}

static noinline void bpf_testmod_retval_capture(int *ptr)
{
	WRITE_ONCE(bpf_testmod_retval_captured, ptr);
}

static noinline int bpf_testmod_retval_store(int value)
{
	WRITE_ONCE(bpf_testmod_retval_state, value);
	return value;
}

static noinline int bpf_testmod_retval_clear(int value)
{
	WRITE_ONCE(bpf_testmod_retval_state, 0);
	return value - 1;
}

/* Constant errors and both return widths */
static __used noinline RETVAL("-22") int bpf_testmod_retval_constant(void)
{
	return -EINVAL;
}

static __used noinline RETVAL("-14") s64 bpf_testmod_retval_wide(void)
{
	return -EFAULT;
}

static __used noinline RETVAL("-1") int bpf_testmod_retval_first_errno(void)
{
	return -1;
}

static __used noinline RETVAL("-4095") int bpf_testmod_retval_last_errno(void)
{
	return -MAX_ERRNO;
}

/*
 * PTR_ERR() of the ERR_PTR() of an inlined helper. Not recognized yet: the
 * error reaches the return through a PHI in an earlier block.
 */
static __always_inline int *bpf_testmod_retval_slot(int *buf, int idx)
{
	if (idx < 0)
		return ERR_PTR(-EINVAL);
	if (idx > 8)
		return ERR_PTR(-EFAULT);
	return &buf[idx];
}

static __used noinline RETVAL("") int bpf_testmod_retval_err_ptr(int *buf, int idx)
{
	int *slot = bpf_testmod_retval_slot(buf, idx);

	if (IS_ERR(slot))
		return PTR_ERR(slot);
	*slot = 1;
	return 0;
}

/* A clean error path may join a dirty success path */
static __used noinline RETVAL("-22") int bpf_testmod_retval_before_store(int *result, int value)
{
	if (value < 0)
		return -EINVAL;
	*result = value;
	return 0;
}

static __used noinline RETVAL("-34,-22") int bpf_testmod_retval_join(int *result, int value)
{
	int ret;

	if (value < 0)
		ret = -EINVAL;
	else if (value > 32)
		ret = -ERANGE;
	else {
		*result = value;
		ret = 0;
	}
	return ret;
}

/*
 * An int error which a long function returns: the PHI of the two calls keeps
 * the sign extension in the block of the return
 */
static __used noinline RETVAL("-22") long bpf_testmod_retval_sign_extend(int value)
{
	int ret;

	if (value < 0)
		ret = -EINVAL;
	else if (value > 32)
		ret = bpf_testmod_retval_store(value);
	else
		ret = bpf_testmod_retval_clear(value);
	return ret;
}

/* An assumption does not make a path dirty */
static __used noinline RETVAL("-22") int bpf_testmod_retval_assume(int value)
{
	__builtin_assume(value > 0);
	return -EINVAL;
}

/* Writes to private stack objects are clean, optnone keeps them in the IR */
static __used noinline RETVAL("-22") __attribute__((optnone))
int bpf_testmod_retval_private_store(int value)
{
	int scratch[2];

	scratch[0] = value;
	scratch[1] = 0;
	return -EINVAL;
}

static __used noinline RETVAL("-22") __attribute__((optnone))
int bpf_testmod_retval_private_memset(void)
{
	char scratch[32];

	__builtin_memset(scratch, 0, sizeof(scratch));
	return -EINVAL;
}

/* An error which is not known exactly is not recorded */
static __used noinline RETVAL("") int bpf_testmod_retval_masked(unsigned int value)
{
	return -1 - (value & 31);
}

static __used noinline RETVAL("") long bpf_testmod_retval_ptr_err(void *ptr, int *state)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	*state = 1;
	return 0;
}

/* Pointer functions are not targets yet */
static __used noinline RETVAL("") void *bpf_testmod_retval_error_pointer(void)
{
	return ERR_PTR(-ENOMEM);
}

/* Every error path has an observable effect */
static __used noinline RETVAL("") int bpf_testmod_retval_argument_store(int *state)
{
	*state = 1;
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_global_store(void)
{
	bpf_testmod_retval_state = 1;
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_volatile_read(int *state)
{
	return READ_ONCE(*state) ? -EINVAL : -ERANGE;
}

static __used noinline RETVAL("") int bpf_testmod_retval_atomic(atomic_t *state)
{
	atomic_inc(state);
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_call(void)
{
	bpf_testmod_retval_effect();
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_barrier(void)
{
	barrier();
	return -EINVAL;
}

static __used noinline RETVAL("")
int bpf_testmod_retval_only_error_is_dirty(int *state, bool reject)
{
	if (reject) {
		*state = 1;
		return -EINVAL;
	}
	return 0;
}

static __used noinline RETVAL("")
int bpf_testmod_retval_lock_held(spinlock_t *lock) __acquires(lock)
{
	spin_lock(lock);
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_stack_escape(void)
{
	int scratch;

	bpf_testmod_retval_capture(&scratch);
	scratch = 1;
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_external_memset(void *dest)
{
	__builtin_memset(dest, 0, 32);
	return -EINVAL;
}

/* Not recognized yet, although they have no side effects */
static __used noinline RETVAL("") int bpf_testmod_retval_balanced_spinlock(spinlock_t *lock)
{
	spin_lock(lock);
	spin_unlock(lock);
	return -EINVAL;
}

static __used noinline RETVAL("") int bpf_testmod_retval_input_errno(int error)
{
	if (error >= -MAX_ERRNO && error < 0)
		return error;
	return 0;
}

/* No ftrace call site, but call padding in __patchable_function_entries on x86 */
static __used noinline RETVAL("") notrace int bpf_testmod_retval_notrace(void)
{
	return -EINVAL;
}

/*
 * A weak definition with an error, replaced by a strong one without errors in
 * bpf_testmod_retval_strong.c
 */
int bpf_testmod_retval_overridden(void);

__weak noinline __attribute__((btf_decl_tag("test_retval:")))
int bpf_testmod_retval_overridden(void)
{
	return -EINVAL;
}

/*
 * Two weak definitions: this one with a side effect is linked first and wins
 * over the one with an error in bpf_testmod_retval_strong.c
 */
int bpf_testmod_retval_two_weak(void);

__weak noinline __attribute__((btf_decl_tag("test_retval:")))
int bpf_testmod_retval_two_weak(void)
{
	bpf_testmod_retval_effect();
	return 0;
}

/*
 * A function on the error injection list gets its tag, but the static rules let
 * programs return any value
 */
static __used noinline RETVAL("-22") int bpf_testmod_retval_injectable(int value)
{
	if (value < 0)
		return -EINVAL;
	bpf_testmod_retval_effect();
	return 0;
}
ALLOW_ERROR_INJECTION(bpf_testmod_retval_injectable, ERRNO);

/* A declared target keeps only its own tags */
static __used noinline RETVAL("") int bpf_testmod_retval_declared(void)
{
	return -EINVAL;
}

BTF_FMODRET_START(bpf_testmod_retval_declared_ids)
BTF_ID_FLAGS(func, bpf_testmod_retval_declared)
BTF_FMODRET_END(bpf_testmod_retval_declared_ids)
