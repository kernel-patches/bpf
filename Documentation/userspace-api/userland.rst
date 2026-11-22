.. SPDX-License-Identifier: GPL-2.0

=============
userland uAPI
=============

Overview
========

A userland is an anonymous-inode control object opened by ``userland_open()`` (not
an ``nsfs`` namespace) that binds a detached namespace set, an initially empty
mount namespace, an owning user namespace, and an init process lifecycle across
build (``USERLAND_INIT``) and live (``USERLAND_RUNNING`` / ``USERLAND_DEAD``) phases.

Flags
=====

.. kernel-doc:: include/uapi/linux/userland.h
   :identifiers: userland_flags

Ioctls
======

.. kernel-doc:: include/uapi/linux/userland.h
   :doc: USERLAND_GET_NSFD

.. kernel-doc:: include/uapi/linux/userland.h
   :doc: USERLAND_SHARE_NSFD

System calls
============

.. kernel-doc:: kernel/userland.c
   :identifiers: sys_userland_open

Process creation
================

.. kernel-doc:: kernel/userland.c
   :doc: CLONE_INTO_USERLAND

Process waiting
===============

.. kernel-doc:: kernel/userland.c
   :doc: P_USERLAND

Signal delivery
===============

.. kernel-doc:: kernel/userland.c
   :doc: pidfd_send_signal

Filesystem configuration
========================

.. kernel-doc:: fs/fsopen.c
   :doc: FSCONFIG_SET_USERLAND

Mount tree installation
=======================

.. kernel-doc:: fs/namespace.c
   :doc: MOVE_MOUNT_T_MNTNS

User namespace ID mapping
=========================

.. kernel-doc:: include/uapi/linux/nsfs.h
   :identifiers: userns_idmap_extent userns_flags userns_idmap

.. kernel-doc:: kernel/user_namespace.c
   :identifiers: sys_userns_set_idmap
