/* SPDX-License-Identifier: GPL-2.0 */
#define LSM_CALL_ARGS_binder_set_context_mgr mgr
#define LSM_CALL_ARGS_binder_transaction from, to
#define LSM_CALL_ARGS_binder_transfer_binder from, to
#define LSM_CALL_ARGS_binder_transfer_file from, to, file
#define LSM_CALL_ARGS_ptrace_access_check child, mode
#define LSM_CALL_ARGS_ptrace_traceme parent
#define LSM_CALL_ARGS_capget target, effective, inheritable, permitted
#define LSM_CALL_ARGS_capset new, old, effective, inheritable, permitted
#define LSM_CALL_ARGS_capable cred, ns, cap, opts
#define LSM_CALL_ARGS_quotactl cmds, type, id, sb
#define LSM_CALL_ARGS_quota_on dentry
#define LSM_CALL_ARGS_syslog type
#define LSM_CALL_ARGS_settime ts, tz
#define LSM_CALL_ARGS_vm_enough_memory mm, pages
#define LSM_CALL_ARGS_bprm_creds_for_exec bprm
#define LSM_CALL_ARGS_bprm_creds_from_file bprm, file
#define LSM_CALL_ARGS_bprm_check_security bprm
#define LSM_CALL_ARGS_bprm_committing_creds bprm
#define LSM_CALL_ARGS_bprm_committed_creds bprm
#define LSM_CALL_ARGS_fs_context_submount fc, reference
#define LSM_CALL_ARGS_fs_context_dup fc, src_sc
#define LSM_CALL_ARGS_fs_context_parse_param fc, param
#define LSM_CALL_ARGS_sb_alloc_security sb
#define LSM_CALL_ARGS_sb_delete sb
#define LSM_CALL_ARGS_sb_free_security sb
#define LSM_CALL_ARGS_sb_free_mnt_opts mnt_opts
#define LSM_CALL_ARGS_sb_eat_lsm_opts orig, mnt_opts
#define LSM_CALL_ARGS_sb_mnt_opts_compat sb, mnt_opts
#define LSM_CALL_ARGS_sb_remount sb, mnt_opts
#define LSM_CALL_ARGS_sb_kern_mount sb
#define LSM_CALL_ARGS_sb_show_options m, sb
#define LSM_CALL_ARGS_sb_statfs dentry
#define LSM_CALL_ARGS_sb_mount dev_name, path, type, flags, data
#define LSM_CALL_ARGS_sb_umount mnt, flags
#define LSM_CALL_ARGS_sb_pivotroot old_path, new_path
#define LSM_CALL_ARGS_sb_set_mnt_opts sb, mnt_opts, kern_flags, set_kern_flags
#define LSM_CALL_ARGS_sb_clone_mnt_opts oldsb, newsb, kern_flags, set_kern_flags
#define LSM_CALL_ARGS_move_mount from_path, to_path
#define LSM_CALL_ARGS_dentry_init_security dentry, mode, name, xattr_name, ctx, ctxlen
#define LSM_CALL_ARGS_dentry_create_files_as dentry, mode, name, old, new
#define LSM_CALL_ARGS_path_unlink dir, dentry
#define LSM_CALL_ARGS_path_mkdir dir, dentry, mode
#define LSM_CALL_ARGS_path_rmdir dir, dentry
#define LSM_CALL_ARGS_path_mknod dir, dentry, mode, dev
#define LSM_CALL_ARGS_path_truncate path
#define LSM_CALL_ARGS_path_symlink dir, dentry, old_name
#define LSM_CALL_ARGS_path_link old_dentry, new_dir, new_dentry
#define LSM_CALL_ARGS_path_rename old_dir, old_dentry, new_dir, new_dentry, flags
#define LSM_CALL_ARGS_path_chmod path, mode
#define LSM_CALL_ARGS_path_chown path, uid, gid
#define LSM_CALL_ARGS_path_chroot path
#define LSM_CALL_ARGS_path_notify path, mask, obj_type
#define LSM_CALL_ARGS_inode_alloc_security inode
#define LSM_CALL_ARGS_inode_free_security inode
#define LSM_CALL_ARGS_inode_init_security inode, dir, qstr, xattrs, xattr_count
#define LSM_CALL_ARGS_inode_init_security_anon inode, name, context_inode
#define LSM_CALL_ARGS_inode_create dir, dentry, mode
#define LSM_CALL_ARGS_inode_link old_dentry, dir, new_dentry
#define LSM_CALL_ARGS_inode_unlink dir, dentry
#define LSM_CALL_ARGS_inode_symlink dir, dentry, old_name
#define LSM_CALL_ARGS_inode_mkdir dir, dentry, mode
#define LSM_CALL_ARGS_inode_rmdir dir, dentry
#define LSM_CALL_ARGS_inode_mknod dir, dentry, mode, dev
#define LSM_CALL_ARGS_inode_rename old_dir, old_dentry, new_dir, new_dentry
#define LSM_CALL_ARGS_inode_readlink dentry
#define LSM_CALL_ARGS_inode_follow_link dentry, inode, rcu
#define LSM_CALL_ARGS_inode_permission inode, mask
#define LSM_CALL_ARGS_inode_setattr dentry, attr
#define LSM_CALL_ARGS_inode_getattr path
#define LSM_CALL_ARGS_inode_setxattr idmap, dentry, name, value, size, flags
#define LSM_CALL_ARGS_inode_post_setxattr dentry, name, value, size, flags
#define LSM_CALL_ARGS_inode_getxattr dentry, name
#define LSM_CALL_ARGS_inode_listxattr dentry
#define LSM_CALL_ARGS_inode_removexattr idmap, dentry, name
#define LSM_CALL_ARGS_inode_set_acl idmap, dentry, acl_name, kacl
#define LSM_CALL_ARGS_inode_get_acl idmap, dentry, acl_name
#define LSM_CALL_ARGS_inode_remove_acl idmap, dentry, acl_name
#define LSM_CALL_ARGS_inode_need_killpriv dentry
#define LSM_CALL_ARGS_inode_killpriv idmap, dentry
#define LSM_CALL_ARGS_inode_getsecurity idmap, inode, name, buffer, alloc
#define LSM_CALL_ARGS_inode_setsecurity inode, name, value, size, flags
#define LSM_CALL_ARGS_inode_listsecurity inode, buffer, buffer_size
#define LSM_CALL_ARGS_inode_getsecid inode, secid
#define LSM_CALL_ARGS_inode_copy_up src, new
#define LSM_CALL_ARGS_inode_copy_up_xattr name
#define LSM_CALL_ARGS_kernfs_init_security kn_dir, kn
#define LSM_CALL_ARGS_file_permission file, mask
#define LSM_CALL_ARGS_file_alloc_security file
#define LSM_CALL_ARGS_file_free_security file
#define LSM_CALL_ARGS_file_ioctl file, cmd, arg
#define LSM_CALL_ARGS_mmap_addr addr
#define LSM_CALL_ARGS_mmap_file file, reqprot, prot, flags
#define LSM_CALL_ARGS_file_mprotect vma, reqprot, prot
#define LSM_CALL_ARGS_file_lock file, cmd
#define LSM_CALL_ARGS_file_fcntl file, cmd, arg
#define LSM_CALL_ARGS_file_set_fowner file
#define LSM_CALL_ARGS_file_send_sigiotask tsk, fown, sig
#define LSM_CALL_ARGS_file_receive file
#define LSM_CALL_ARGS_file_open file
#define LSM_CALL_ARGS_file_truncate file
#define LSM_CALL_ARGS_task_alloc task, clone_flags
#define LSM_CALL_ARGS_task_free task
#define LSM_CALL_ARGS_cred_alloc_blank cred, gfp
#define LSM_CALL_ARGS_cred_free cred
#define LSM_CALL_ARGS_cred_prepare new, old, gfp
#define LSM_CALL_ARGS_cred_transfer new, old
#define LSM_CALL_ARGS_cred_getsecid c, secid
#define LSM_CALL_ARGS_kernel_act_as new, secid
#define LSM_CALL_ARGS_kernel_create_files_as new, inode
#define LSM_CALL_ARGS_kernel_module_request kmod_name
#define LSM_CALL_ARGS_kernel_load_data id, contents
#define LSM_CALL_ARGS_kernel_post_load_data buf, size, id, description
#define LSM_CALL_ARGS_kernel_read_file file, id, contents
#define LSM_CALL_ARGS_kernel_post_read_file file, buf, size, id
#define LSM_CALL_ARGS_task_fix_setuid new, old, flags
#define LSM_CALL_ARGS_task_fix_setgid new, old, flags
#define LSM_CALL_ARGS_task_fix_setgroups new, old
#define LSM_CALL_ARGS_task_setpgid p, pgid
#define LSM_CALL_ARGS_task_getpgid p
#define LSM_CALL_ARGS_task_getsid p
#define LSM_CALL_ARGS_current_getsecid_subj secid
#define LSM_CALL_ARGS_task_getsecid_obj p, secid
#define LSM_CALL_ARGS_task_setnice p, nice
#define LSM_CALL_ARGS_task_setioprio p, ioprio
#define LSM_CALL_ARGS_task_getioprio p
#define LSM_CALL_ARGS_task_prlimit cred, tcred, flags
#define LSM_CALL_ARGS_task_setrlimit p, resource, new_rlim
#define LSM_CALL_ARGS_task_setscheduler p
#define LSM_CALL_ARGS_task_getscheduler p
#define LSM_CALL_ARGS_task_movememory p
#define LSM_CALL_ARGS_task_kill p, info, sig, cred
#define LSM_CALL_ARGS_task_prctl option, arg2, arg3, arg4, arg5
#define LSM_CALL_ARGS_task_to_inode p, inode
#define LSM_CALL_ARGS_userns_create cred
#define LSM_CALL_ARGS_ipc_permission ipcp, flag
#define LSM_CALL_ARGS_ipc_getsecid ipcp, secid
#define LSM_CALL_ARGS_msg_msg_alloc_security msg
#define LSM_CALL_ARGS_msg_msg_free_security msg
#define LSM_CALL_ARGS_msg_queue_alloc_security perm
#define LSM_CALL_ARGS_msg_queue_free_security perm
#define LSM_CALL_ARGS_msg_queue_associate perm, msqflg
#define LSM_CALL_ARGS_msg_queue_msgctl perm, cmd
#define LSM_CALL_ARGS_msg_queue_msgsnd perm, msg, msqflg
#define LSM_CALL_ARGS_msg_queue_msgrcv perm, msg, target, type, mode
#define LSM_CALL_ARGS_shm_alloc_security perm
#define LSM_CALL_ARGS_shm_free_security perm
#define LSM_CALL_ARGS_shm_associate perm, shmflg
#define LSM_CALL_ARGS_shm_shmctl perm, cmd
#define LSM_CALL_ARGS_shm_shmat perm, shmaddr, shmflg
#define LSM_CALL_ARGS_sem_alloc_security perm
#define LSM_CALL_ARGS_sem_free_security perm
#define LSM_CALL_ARGS_sem_associate perm, semflg
#define LSM_CALL_ARGS_sem_semctl perm, cmd
#define LSM_CALL_ARGS_sem_semop perm, sops, nsops, alter
#define LSM_CALL_ARGS_netlink_send sk, skb
#define LSM_CALL_ARGS_d_instantiate dentry, inode
#define LSM_CALL_ARGS_getprocattr p, name, value
#define LSM_CALL_ARGS_setprocattr name, value, size
#define LSM_CALL_ARGS_ismaclabel name
#define LSM_CALL_ARGS_secid_to_secctx secid, secdata, seclen
#define LSM_CALL_ARGS_secctx_to_secid secdata, seclen, secid
#define LSM_CALL_ARGS_release_secctx secdata, seclen
#define LSM_CALL_ARGS_inode_invalidate_secctx inode
#define LSM_CALL_ARGS_inode_notifysecctx inode, ctx, ctxlen
#define LSM_CALL_ARGS_inode_setsecctx dentry, ctx, ctxlen
#define LSM_CALL_ARGS_inode_getsecctx inode, ctx, ctxlen
#define LSM_CALL_ARGS_post_notification w_cred, cred, n
#define LSM_CALL_ARGS_watch_key key
#define LSM_CALL_ARGS_unix_stream_connect sock, other, newsk
#define LSM_CALL_ARGS_unix_may_send sock, other
#define LSM_CALL_ARGS_socket_create family, type, protocol, kern
#define LSM_CALL_ARGS_socket_post_create sock, family, type, protocol, kern
#define LSM_CALL_ARGS_socket_socketpair socka, sockb
#define LSM_CALL_ARGS_socket_bind sock, address, addrlen
#define LSM_CALL_ARGS_socket_connect sock, address, addrlen
#define LSM_CALL_ARGS_socket_listen sock, backlog
#define LSM_CALL_ARGS_socket_accept sock, newsock
#define LSM_CALL_ARGS_socket_sendmsg sock, msg, size
#define LSM_CALL_ARGS_socket_recvmsg sock, msg, size, flags
#define LSM_CALL_ARGS_socket_getsockname sock
#define LSM_CALL_ARGS_socket_getpeername sock
#define LSM_CALL_ARGS_socket_getsockopt sock, level, optname
#define LSM_CALL_ARGS_socket_setsockopt sock, level, optname
#define LSM_CALL_ARGS_socket_shutdown sock, how
#define LSM_CALL_ARGS_socket_sock_rcv_skb sk, skb
#define LSM_CALL_ARGS_socket_getpeersec_stream sock, optval, optlen, len
#define LSM_CALL_ARGS_socket_getpeersec_dgram sock, skb, secid
#define LSM_CALL_ARGS_sk_alloc_security sk, family, priority
#define LSM_CALL_ARGS_sk_free_security sk
#define LSM_CALL_ARGS_sk_clone_security sk, newsk
#define LSM_CALL_ARGS_sk_getsecid sk, secid
#define LSM_CALL_ARGS_sock_graft sk, parent
#define LSM_CALL_ARGS_inet_conn_request sk, skb, req
#define LSM_CALL_ARGS_inet_csk_clone newsk, req
#define LSM_CALL_ARGS_inet_conn_established sk, skb
#define LSM_CALL_ARGS_secmark_relabel_packet secid
#define LSM_CALL_ARGS_secmark_refcount_inc
#define LSM_CALL_ARGS_secmark_refcount_dec
#define LSM_CALL_ARGS_req_classify_flow req, flic
#define LSM_CALL_ARGS_tun_dev_alloc_security security
#define LSM_CALL_ARGS_tun_dev_free_security security
#define LSM_CALL_ARGS_tun_dev_create
#define LSM_CALL_ARGS_tun_dev_attach_queue security
#define LSM_CALL_ARGS_tun_dev_attach sk, security
#define LSM_CALL_ARGS_tun_dev_open security
#define LSM_CALL_ARGS_sctp_assoc_request asoc, skb
#define LSM_CALL_ARGS_sctp_bind_connect sk, optname, address, addrlen
#define LSM_CALL_ARGS_sctp_sk_clone asoc, sk, newsk
#define LSM_CALL_ARGS_sctp_assoc_established asoc, skb
#define LSM_CALL_ARGS_mptcp_add_subflow sk, ssk
#define LSM_CALL_ARGS_ib_pkey_access sec, subnet_prefix, pkey
#define LSM_CALL_ARGS_ib_endport_manage_subnet sec, dev_name, port_num
#define LSM_CALL_ARGS_ib_alloc_security sec
#define LSM_CALL_ARGS_ib_free_security sec
#define LSM_CALL_ARGS_xfrm_policy_alloc_security ctxp, sec_ctx, gfp
#define LSM_CALL_ARGS_xfrm_policy_clone_security old_ctx, new_ctx
#define LSM_CALL_ARGS_xfrm_policy_free_security ctx
#define LSM_CALL_ARGS_xfrm_policy_delete_security ctx
#define LSM_CALL_ARGS_xfrm_state_alloc x, sec_ctx
#define LSM_CALL_ARGS_xfrm_state_alloc_acquire x, polsec, secid
#define LSM_CALL_ARGS_xfrm_state_free_security x
#define LSM_CALL_ARGS_xfrm_state_delete_security x
#define LSM_CALL_ARGS_xfrm_policy_lookup ctx, fl_secid
#define LSM_CALL_ARGS_xfrm_state_pol_flow_match x, xp, flic
#define LSM_CALL_ARGS_xfrm_decode_session skb, secid, ckall
#define LSM_CALL_ARGS_key_alloc key, cred, flags
#define LSM_CALL_ARGS_key_free key
#define LSM_CALL_ARGS_key_permission key_ref, cred, need_perm
#define LSM_CALL_ARGS_key_getsecurity key, buffer
#define LSM_CALL_ARGS_audit_rule_init field, op, rulestr, lsmrule
#define LSM_CALL_ARGS_audit_rule_known krule
#define LSM_CALL_ARGS_audit_rule_match secid, field, op, lsmrule
#define LSM_CALL_ARGS_audit_rule_free lsmrule
#define LSM_CALL_ARGS_bpf cmd, attr, size
#define LSM_CALL_ARGS_bpf_map map, fmode
#define LSM_CALL_ARGS_bpf_prog prog
#define LSM_CALL_ARGS_bpf_map_alloc_security map
#define LSM_CALL_ARGS_bpf_map_free_security map
#define LSM_CALL_ARGS_bpf_prog_alloc_security aux
#define LSM_CALL_ARGS_bpf_prog_free_security aux
#define LSM_CALL_ARGS_locked_down what
#define LSM_CALL_ARGS_perf_event_open attr, type
#define LSM_CALL_ARGS_perf_event_alloc event
#define LSM_CALL_ARGS_perf_event_free event
#define LSM_CALL_ARGS_perf_event_read event
#define LSM_CALL_ARGS_perf_event_write event
#define LSM_CALL_ARGS_uring_override_creds new
#define LSM_CALL_ARGS_uring_sqpoll
#define LSM_CALL_ARGS_uring_cmd ioucmd
