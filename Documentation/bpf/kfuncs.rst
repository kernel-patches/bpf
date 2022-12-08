=============================
BPF Kernel Functions (kfuncs)
=============================

1. Introduction
===============

BPF Kernel Functions or more commonly known as kfuncs are functions in the Linux
kernel which are exposed for use by BPF programs. Unlike normal BPF helpers,
kfuncs do not have a stable interface and can change from one kernel release to
another. Hence, BPF programs need to be updated in response to changes in the
kernel.

2. Defining a kfunc
===================

There are two ways to expose a kernel function to BPF programs, either make an
existing function in the kernel visible, or add a new wrapper for BPF. In both
cases, care must be taken that BPF program can only call such function in a
valid context. To enforce this, visibility of a kfunc can be per program type.

If you are not creating a BPF wrapper for existing kernel function, skip ahead
to :ref:`BPF_kfunc_nodef`.

2.1 Creating a wrapper kfunc
----------------------------

When defining a wrapper kfunc, the wrapper function should have extern linkage.
This prevents the compiler from optimizing away dead code, as this wrapper kfunc
is not invoked anywhere in the kernel itself. It is not necessary to provide a
prototype in a header for the wrapper kfunc.

An example is given below::

        /* Disables missing prototype warnings */
        __diag_push();
        __diag_ignore_all("-Wmissing-prototypes",
                          "Global kfuncs as their definitions will be in BTF");

        struct task_struct *bpf_find_get_task_by_vpid(pid_t nr)
        {
                return find_get_task_by_vpid(nr);
        }

        __diag_pop();

A wrapper kfunc is often needed when we need to annotate parameters of the
kfunc. Otherwise one may directly make the kfunc visible to the BPF program by
registering it with the BPF subsystem. See :ref:`BPF_kfunc_nodef`.

2.2 Annotating kfunc parameters
-------------------------------

Similar to BPF helpers, there is sometime need for additional context required
by the verifier to make the usage of kernel functions safer and more useful.
Hence, we can annotate a parameter by suffixing the name of the argument of the
kfunc with a __tag, where tag may be one of the supported annotations.

2.2.1 __sz Annotation
---------------------

This annotation is used to indicate a memory and size pair in the argument list.
An example is given below::

        void bpf_memzero(void *mem, int mem__sz)
        {
        ...
        }

Here, the verifier will treat first argument as a PTR_TO_MEM, and second
argument as its size. By default, without __sz annotation, the size of the type
of the pointer is used. Without __sz annotation, a kfunc cannot accept a void
pointer.

2.2.2 __k Annotation
--------------------

This annotation is only understood for scalar arguments, where it indicates that
the verifier must check the scalar argument to be a known constant, which does
not indicate a size parameter, and the value of the constant is relevant to the
safety of the program.

An example is given below::

        void *bpf_obj_new(u32 local_type_id__k, ...)
        {
        ...
        }

Here, bpf_obj_new uses local_type_id argument to find out the size of that type
ID in program's BTF and return a sized pointer to it. Each type ID will have a
distinct size, hence it is crucial to treat each such call as distinct when
values don't match during verifier state pruning checks.

Hence, whenever a constant scalar argument is accepted by a kfunc which is not a
size parameter, and the value of the constant matters for program safety, __k
suffix should be used.

.. _BPF_kfunc_nodef:

2.3 Using an existing kernel function
-------------------------------------

When an existing function in the kernel is fit for consumption by BPF programs,
it can be directly registered with the BPF subsystem. However, care must still
be taken to review the context in which it will be invoked by the BPF program
and whether it is safe to do so.

2.4 Annotating kfuncs
---------------------

In addition to kfuncs' arguments, verifier may need more information about the
type of kfunc(s) being registered with the BPF subsystem. To do so, we define
flags on a set of kfuncs as follows::

        BTF_SET8_START(bpf_task_set)
        BTF_ID_FLAGS(func, bpf_get_task_pid, KF_ACQUIRE | KF_RET_NULL)
        BTF_ID_FLAGS(func, bpf_put_pid, KF_RELEASE)
        BTF_SET8_END(bpf_task_set)

This set encodes the BTF ID of each kfunc listed above, and encodes the flags
along with it. Ofcourse, it is also allowed to specify no flags.

2.4.1 KF_ACQUIRE flag
---------------------

The KF_ACQUIRE flag is used to indicate that the kfunc returns a pointer to a
refcounted object. The verifier will then ensure that the pointer to the object
is eventually released using a release kfunc, or transferred to a map using a
referenced kptr (by invoking bpf_kptr_xchg). If not, the verifier fails the
loading of the BPF program until no lingering references remain in all possible
explored states of the program.

2.4.2 KF_RET_NULL flag
----------------------

The KF_RET_NULL flag is used to indicate that the pointer returned by the kfunc
may be NULL. Hence, it forces the user to do a NULL check on the pointer
returned from the kfunc before making use of it (dereferencing or passing to
another helper). This flag is often used in pairing with KF_ACQUIRE flag, but
both are orthogonal to each other.

2.4.3 KF_RELEASE flag
---------------------

The KF_RELEASE flag is used to indicate that the kfunc releases the pointer
passed in to it. There can be only one referenced pointer that can be passed in.
All copies of the pointer being released are invalidated as a result of invoking
kfunc with this flag.

2.4.4 KF_KPTR_GET flag
----------------------

The KF_KPTR_GET flag is used to indicate that the kfunc takes the first argument
as a pointer to kptr, safely increments the refcount of the object it points to,
and returns a reference to the user. The rest of the arguments may be normal
arguments of a kfunc. The KF_KPTR_GET flag should be used in conjunction with
KF_ACQUIRE and KF_RET_NULL flags.

2.4.5 KF_TRUSTED_ARGS flag
--------------------------

The KF_TRUSTED_ARGS flag is used for kfuncs taking pointer arguments. It
indicates that the all pointer arguments are valid, and that all pointers to
BTF objects have been passed in their unmodified form (that is, at a zero
offset, and without having been obtained from walking another pointer).

There are two types of pointers to kernel objects which are considered "valid":

1. Pointers which are passed as tracepoint or struct_ops callback arguments.
2. Pointers which were returned from a KF_ACQUIRE or KF_KPTR_GET kfunc.

Pointers to non-BTF objects (e.g. scalar pointers) may also be passed to
KF_TRUSTED_ARGS kfuncs, and may have a non-zero offset.

The definition of "valid" pointers is subject to change at any time, and has
absolutely no ABI stability guarantees.

2.4.6 KF_SLEEPABLE flag
-----------------------

The KF_SLEEPABLE flag is used for kfuncs that may sleep. Such kfuncs can only
be called by sleepable BPF programs (BPF_F_SLEEPABLE).

2.4.7 KF_DESTRUCTIVE flag
--------------------------

The KF_DESTRUCTIVE flag is used to indicate functions calling which is
destructive to the system. For example such a call can result in system
rebooting or panicking. Due to this additional restrictions apply to these
calls. At the moment they only require CAP_SYS_BOOT capability, but more can be
added later.

2.4.8 KF_RCU flag
-----------------

The KF_RCU flag is used for kfuncs which have a rcu ptr as its argument.
When used together with KF_ACQUIRE, it indicates the kfunc should have a
single argument which must be a trusted argument or a MEM_RCU pointer.
The argument may have reference count of 0 and the kfunc must take this
into consideration.

2.5 Registering the kfuncs
--------------------------

Once the kfunc is prepared for use, the final step to making it visible is
registering it with the BPF subsystem. Registration is done per BPF program
type. An example is shown below::

        BTF_SET8_START(bpf_task_set)
        BTF_ID_FLAGS(func, bpf_get_task_pid, KF_ACQUIRE | KF_RET_NULL)
        BTF_ID_FLAGS(func, bpf_put_pid, KF_RELEASE)
        BTF_SET8_END(bpf_task_set)

        static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
                .owner = THIS_MODULE,
                .set   = &bpf_task_set,
        };

        static int init_subsystem(void)
        {
                return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_task_kfunc_set);
        }
        late_initcall(init_subsystem);

3. Core kfuncs
==============

The BPF subsystem provides a number of "core" kfuncs that are potentially
applicable to a wide variety of different possible use cases and programs.
Those kfuncs are documented here.

3.1 struct task_struct * kfuncs
-------------------------------

There are a number of kfuncs that allow ``struct task_struct *`` objects to be
used as kptrs:

.. kernel-doc:: kernel/bpf/helpers.c
   :identifiers: bpf_task_acquire bpf_task_release

These kfuncs are useful when you want to acquire or release a reference to a
``struct task_struct *`` that was passed as e.g. a tracepoint arg, or a
struct_ops callback arg. For example:

.. code-block:: c

	/**
	 * A trivial example tracepoint program that shows how to
	 * acquire and release a struct task_struct * pointer.
	 */
	SEC("tp_btf/task_newtask")
	int BPF_PROG(task_acquire_release_example, struct task_struct *task, u64 clone_flags)
	{
		struct task_struct *acquired;

		acquired = bpf_task_acquire(task);

		/*
		 * In a typical program you'd do something like store
		 * the task in a map, and the map will automatically
		 * release it later. Here, we release it manually.
		 */
		bpf_task_release(acquired);
		return 0;
	}

----

A BPF program can also look up a task from a pid. This can be useful if the
caller doesn't have a trusted pointer to a ``struct task_struct *`` object that
it can acquire a reference on with bpf_task_acquire().

.. kernel-doc:: kernel/bpf/helpers.c
   :identifiers: bpf_task_from_pid

Here is an example of it being used:

.. code-block:: c

	SEC("tp_btf/task_newtask")
	int BPF_PROG(task_get_pid_example, struct task_struct *task, u64 clone_flags)
	{
		struct task_struct *lookup;

		lookup = bpf_task_from_pid(task->pid);
		if (!lookup)
			/* A task should always be found, as %task is a tracepoint arg. */
			return -ENOENT;

		if (lookup->pid != task->pid) {
			/* bpf_task_from_pid() looks up the task via its
			 * globally-unique pid from the init_pid_ns. Thus,
			 * the pid of the lookup task should always be the
			 * same as the input task.
			 */
			bpf_task_release(lookup);
			return -EINVAL;
		}

		/* bpf_task_from_pid() returns an acquired reference,
		 * so it must be dropped before returning from the
		 * tracepoint handler.
		 */
		bpf_task_release(lookup);
		return 0;
	}

3.2 struct cgroup * kfuncs
--------------------------

``struct cgroup *`` objects also have acquire and release functions:

.. kernel-doc:: kernel/bpf/helpers.c
   :identifiers: bpf_cgroup_acquire bpf_cgroup_release

These kfuncs are used in exactly the same manner as bpf_task_acquire() and
bpf_task_release() respectively, so we won't provide examples for them.

----

You may also acquire a reference to a ``struct cgroup`` kptr that's already
stored in a map using bpf_cgroup_kptr_get():

.. kernel-doc:: kernel/bpf/helpers.c
   :identifiers: bpf_cgroup_kptr_get

Here's an example of how it can be used:

.. code-block:: c

	/* struct containing the struct task_struct kptr which is actually stored in the map. */
	struct __cgroups_kfunc_map_value {
		struct cgroup __kptr_ref * cgroup;
	};

	/* The map containing struct __cgroups_kfunc_map_value entries. */
	struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__type(key, int);
		__type(value, struct __cgroups_kfunc_map_value);
		__uint(max_entries, 1);
	} __cgroups_kfunc_map SEC(".maps");

	/* ... */

	/**
	 * A simple example tracepoint program showing how a
	 * struct cgroup kptr that is stored in a map can
	 * be acquired using the bpf_cgroup_kptr_get() kfunc.
	 */
	 SEC("tp_btf/cgroup_mkdir")
	 int BPF_PROG(cgroup_kptr_get_example, struct cgroup *cgrp, const char *path)
	 {
		struct cgroup *kptr;
		struct __cgroups_kfunc_map_value *v;
		s32 id = cgrp->self.id;

		/* Assume a cgroup kptr was previously stored in the map. */
		v = bpf_map_lookup_elem(&__cgroups_kfunc_map, &id);
		if (!v)
			return -ENOENT;

		/* Acquire a reference to the cgroup kptr that's already stored in the map. */
		kptr = bpf_cgroup_kptr_get(&v->cgroup);
		if (!kptr)
			/* If no cgroup was present in the map, it's because
			 * we're racing with another CPU that removed it with
			 * bpf_kptr_xchg() between the bpf_map_lookup_elem()
			 * above, and our call to bpf_cgroup_kptr_get().
			 * bpf_cgroup_kptr_get() internally safely handles this
			 * race, and will return NULL if the task is no longer
			 * present in the map by the time we invoke the kfunc.
			 */
			return -EBUSY;

		/* Free the reference we just took above. Note that the
		 * original struct cgroup kptr is still in the map. It will
		 * be freed either at a later time if another context deletes
		 * it from the map, or automatically by the BPF subsystem if
		 * it's still present when the map is destroyed.
		 */
		bpf_cgroup_release(kptr);

		return 0;
        }

----

Another kfunc available for interacting with ``struct cgroup *`` objects is
bpf_cgroup_ancestor(). This allows callers to access the ancestor of a cgroup,
and return it as a cgroup kptr.

.. kernel-doc:: kernel/bpf/helpers.c
   :identifiers: bpf_cgroup_ancestor

Eventually, BPF should be updated to allow this to happen with a normal memory
load in the program itself. This is currently not possible without more work in
the verifier. bpf_cgroup_ancestor() can be used as follows:

.. code-block:: c

	/**
	 * Simple tracepoint example that illustrates how a cgroup's
	 * ancestor can be accessed using bpf_cgroup_ancestor().
	 */
	SEC("tp_btf/cgroup_mkdir")
	int BPF_PROG(cgrp_ancestor_example, struct cgroup *cgrp, const char *path)
	{
		struct cgroup *parent;

		/* The parent cgroup resides at the level before the current cgroup's level. */
		parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1);
		if (!parent)
			return -ENOENT;

		bpf_printk("Parent id is %d", parent->self.id);

		/* Return the parent cgroup that was acquired above. */
		bpf_cgroup_release(parent);
		return 0;
	}
