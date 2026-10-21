.. SPDX-License-Identifier: GPL-2.0

.. _fs_kfuncs-header-label:

=====================
BPF filesystem kfuncs
=====================

BPF LSM programs need to access filesystem data from LSM hooks. The following
BPF kfuncs can be used to get these data.

 * ``bpf_get_file_xattr()``

 * ``bpf_get_fsverity_digest()``

 * ``bpf_path_getattr()``

To avoid recursions, these kfuncs follow the following rules:

1. These kfuncs are only permitted from BPF LSM function.
2. These kfuncs should not call into other LSM hooks, i.e. security_*(). For
   example, ``bpf_get_file_xattr()`` does not use ``vfs_getxattr()``, because
   the latter calls LSM hook ``security_inode_getxattr``.

File attributes
===============

``bpf_path_getattr()`` queries filesystem attributes with statx(2) semantics,
including overlayfs inode and device identity. Use a trusted hook argument,
such as the path in ``lsm.s/inode_getattr`` or ``&file->f_path`` in
``lsm.s/file_open``.

.. kernel-doc:: fs/bpf_fs_kfuncs.c
   :identifiers: bpf_file_stat bpf_path_getattr
