=============
BPF OOM Policy
=============

The Out Of Memory Killer (aka OOM Killer) is invoked when the system is
critically low on memory. The in-kernel implementation is to iterate over
all tasks in the specific oom domain (all tasks for global and all members
of memcg tree for hard limit oom) and select a victim based some heuristic
policy to kill.

Specifically:

1. Begin to iterate tasks using ``oom_evaluate_task()`` and find a valid (killable)
   victim in iteration N, select it.

2. In iteration N + 1, N + 2..., we compare the current iteration task with the
   previous selected task, if current is more suitable then select it.

3. finally we get a victim to kill.

However, this does not meet the needs of users in some special scenarios. Using
the eBPF capabilities, We can implement customized OOM policies to meet needs.

Developer API:
==================

bpf_oom_evaluate_task
----------------------

``bpf_oom_evaluate_task`` is a new interface hooking into ``oom_evaluate_task()``
which is used to bypass the in-kernel selection logic. Users can customize their
victim selection policy through BPF programs attached to it.
::

    int bpf_oom_evaluate_task(struct task_struct *task,
                                struct oom_control *oc);

return value::

    NO_BPF_POLICY     no bpf policy and would fallback to the in-kernel selection
    BPF_EVAL_ABORT    abort the selection (exit from current selection loop)
    BPF_EVAL_NEXT     ignore the task
    BPF_EAVL_SELECT   select the current task

Suppose we want to select a victim based on the specified pid when OOM is
invoked, we can use the following BPF program::

    SEC("fmod_ret/bpf_oom_evaluate_task")
    int BPF_PROG(bpf_oom_evaluate_task, struct task_struct *task, struct oom_control *oc)
    {
        if (task->pid == target_pid)
            return BPF_EAVL_SELECT;
        return BPF_EVAL_NEXT;
    }

bpf_set_policy_name
---------------------

``bpf_set_policy_name`` is a interface hooking before the start of victim selection. We can
set policy's name in the attached program, so dump_header() can identify different policies
when reporting messages. We can set policy's name through kfunc ``set_oom_policy_name``
::

    SEC("fentry/bpf_set_policy_name")
    int BPF_PROG(set_police_name_k, struct oom_control *oc)
    {
	    char name[] = "my_policy";
	    set_oom_policy_name(oc, name, sizeof(name));
	    return 0;
    }