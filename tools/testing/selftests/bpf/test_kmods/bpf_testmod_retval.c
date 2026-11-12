// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for resolve_btfids --fmodret_scan, which tags the functions that
 * return errors as fmod_ret targets. prog_tests/fmodret_retval.c has the tags
 * which it expects. A part of bpf_testmod.c.
 */

/* bpf_testmod_test_write() calls it and returns what it gets */
static noinline int bpf_testmod_retval_called(size_t len)
{
	if (len == 7)
		return -EFBIG;
	return len ? 0 : -EINVAL;
}

static __used noinline long bpf_testmod_retval_long(int value)
{
	return value ? -EFAULT : -ENOSPC;
}

/* 0xffffffea is not an error in 64 bits */
static __used noinline u64 bpf_testmod_retval_zero_extended(int value)
{
	return value ? (u32)-EINVAL : 0;
}

/* -1 may be "less" or "none": it counts only next to another error */
static __used noinline int bpf_testmod_retval_minus_one(int value)
{
	return value ? -1 : 0;
}

static __used noinline int bpf_testmod_retval_eperm(int value)
{
	if (value < 0)
		return -EPERM;
	return value > 8 ? -ENOENT : value;
}

/* Errors which tell the caller that something goes on are not listed */
static __used noinline int bpf_testmod_retval_denied(int a, int b, int c, int d)
{
	if (a > 1)
		return -EMSGSIZE;
	if (a)
		return -EACCES;
	if (b)
		return -EAGAIN;
	if (c)
		return -EINPROGRESS;
	return d ? -ERESTARTSYS : -EIOCBQUEUED;
}

/* A caller which gets -EBUSY relies on the unlock */
static __used noinline int bpf_testmod_retval_effect(struct mutex *lock, int value)
{
	if (value < 0)
		return -EINVAL;
	mutex_unlock(lock);
	return value > 8 ? -EBUSY : value;
}

/* The errors are set before the unlock. The pointer moves to another register */
static __used noinline int bpf_testmod_retval_effect_late(int value, struct mutex *lock)
{
	int err = 0;

	if (value < 0)
		return -EINVAL;
	if (value == 1)
		err = -EBUSY;
	else if (value == 2)
		err = -ENOSPC;
	mutex_unlock(lock);
	return err;
}

/* The callee can fail, the pointer is loaded, a path goes around the unlock */
static __used noinline int bpf_testmod_retval_no_effect(struct mutex *lock, struct mutex **other,
							int value)
{
	if (!mutex_trylock(lock))
		return -EBUSY;
	mutex_unlock(*other);
	if (value < 0)
		return -EINVAL;
	if (value & 1)
		mutex_unlock(lock);
	return mutex_is_locked(lock) ? -ENOSPC : 0;
}

/* PTR_ERR() of the ERR_PTR() of an inlined helper */
static __always_inline int *bpf_testmod_retval_slot(int *buf, int idx)
{
	if (idx < 0)
		return ERR_PTR(-ERANGE);
	return idx > 8 ? ERR_PTR(-EFAULT) : &buf[idx];
}

static __used noinline int bpf_testmod_retval_err_ptr(int *buf, int idx)
{
	int *slot = bpf_testmod_retval_slot(buf, idx);

	if (IS_ERR(slot))
		return PTR_ERR(slot);
	*slot = 1;
	return 0;
}

/* GCC for x86-64: neg, sbb, and */
static __used noinline int bpf_testmod_retval_no_branch(unsigned long left)
{
	return left ? -EFAULT : 0;
}

/* Not an integer, and an error which is not returned */
static __used noinline void *bpf_testmod_retval_pointer(int value)
{
	return value ? ERR_PTR(-EINVAL) : NULL;
}

static __used noinline int bpf_testmod_retval_argument(int value)
{
	return bpf_testmod_retval_minus_one(value ? -EINVAL : -ENOMEM) + 1;
}

/* Gone before a program can attach */
static __used noinline __init int bpf_testmod_retval_init(int value)
{
	return value ? -EINVAL : -ENOMEM;
}
