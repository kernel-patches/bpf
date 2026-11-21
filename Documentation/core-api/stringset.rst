.. SPDX-License-Identifier: GPL-2.0+

=========
Stringset
=========

Overview
========

A stringset is a set of strings, intended for resource tagging where
metadata about a resource is represented simply by a name. The public
API can be found in ``<linux/stringset.h>``.


Initialization and Destruction
==============================

A stringset must be initialized before use::

    struct stringset set;
    stringset_init(&set);

``DEFINE_STRINGSET()`` declares a stringset and initializes it in
one step::

    DEFINE_STRINGSET(set);

Before adding strings, allocate capacity::

    if (!stringset_alloc(&set, num_strings, GFP_KERNEL))
        return -ENOMEM;

When finished, release all resources::

    stringset_destroy(&set);

This frees all strings and the array. The stringset is reinitialized
and may be reused by calling ``stringset_alloc()`` again.


Adding Strings
==============

Two functions are provided for adding strings. Both require that
sufficient capacity has been allocated via ``stringset_alloc()``.

``stringset_add()``
    Adds a string that is already in kmalloc'd memory. On success,
    the stringset takes ownership of the string and frees it when
    the stringset is destroyed, or at ``stringset_finalize()`` if it
    is a duplicate::

        char *str = kstrdup("example", GFP_KERNEL);
        if (!str || !stringset_add(&set, str))
            kfree(str);  /* failed, caller must free */

``stringset_add_dup()``
    Duplicates the string internally. The caller retains ownership
    of the original string::

        if (!stringset_add_dup(&set, "example", GFP_KERNEL))
            return -ENOMEM;

Both functions return true on success, false on failure. Strings must
not be added after ``stringset_finalize()`` has been called. Pass
``GFP_ATOMIC`` to ``stringset_add_dup()`` in atomic context.


Finalizing
==========

After adding all strings, the stringset must be finalized before
querying::

    stringset_finalize(&set);

This sorts the array to enable efficient binary search and removes
any duplicate strings. Calling ``stringset_is_member()`` or
``stringset_intersection()`` on a non-finalized stringset warns and
returns ``false``.


Querying Strings
================

``stringset_is_empty()``
    Returns true if the stringset contains no strings.

``stringset_count()``
    Returns the number of strings in the stringset. Before finalization,
    this is the number of strings added; after finalization, this is
    the number of unique strings.

``stringset_is_member()``
    Returns true if a string is present in the stringset. Uses binary
    search for O(log N) complexity::

        if (stringset_is_member(&set, "example"))
            pr_info("string found\n");

``stringset_intersection()``
    Returns true if two stringsets share at least one common string.
    Uses merge-style comparison for O(N+M) complexity::

        if (stringset_intersection(&set1, &set2))
            pr_info("sets overlap\n");


Iteration
=========

Use ``stringset_for_each()`` to iterate over all strings::

    unsigned int index;
    char *str;

    stringset_for_each(&set, index, str)
        pr_info("string: %s\n", str);

Callers should not depend on the order in which strings are returned.
Modifying the stringset during iteration produces undefined behavior.


Copying
=======

``stringset_copy()`` duplicates all strings from one stringset to
another::

    struct stringset copy;

    stringset_init(&copy);
    if (!stringset_copy(&copy, &original, GFP_KERNEL))
        pr_err("copy failed\n");

The source stringset must be finalized before copying; copying an
unfinalized stringset warns and returns failure. The destination
stringset is initialized and ready for queries after this function
returns (no separate ``stringset_finalize()`` call is needed). Each
string is duplicated, so the two stringsets are fully independent after
copying.


Typical Usage Pattern
=====================

A typical usage pattern for building a stringset::

    struct stringset set;

    stringset_init(&set);
    if (!stringset_alloc(&set, count, GFP_KERNEL))
        return -ENOMEM;

    for (i = 0; i < count; i++) {
        if (!stringset_add_dup(&set, strings[i], GFP_KERNEL)) {
            stringset_destroy(&set);
            return -ENOMEM;
        }
    }
    stringset_finalize(&set);

    /* Now safe to query */
    if (stringset_is_member(&set, "target"))
        do_something();

    stringset_destroy(&set);


Thread Safety
=============

Stringsets have no internal locking. Callers provide synchronization
between writers and readers.

The build-and-finalize phase mutates the stringset; the post-finalize
query phase reads from it. The two phases must be separated by a
publication boundary, because ``stringset_finalize()`` itself carries
no memory barrier. A reader that observes the finalized stringset
before the writer's stores have propagated may see a stale
``ss_count`` or a partially populated ``ss_strings[]`` array.

Three publication patterns are sufficient:

* Lock release after ``stringset_finalize()``, lock acquire before
  each query. The matching unlock/lock pair supplies release and
  acquire ordering.

* ``rcu_assign_pointer()`` of the stringset pointer after
  ``stringset_finalize()``, paired with ``rcu_dereference()`` inside
  an RCU read-side critical section on the reader.

* ``smp_store_release()`` of the stringset pointer after
  ``stringset_finalize()``, paired with ``smp_load_acquire()`` on the
  reader.

Once published, the stringset must remain immutable until no further
readers can observe it. ``stringset_destroy()`` is not safe against
concurrent readers, and ``stringset_finalize()`` must not be called
more than once. With RCU publication, callers typically defer
destruction to a grace period (``synchronize_rcu()`` before
``stringset_destroy()``, or ``stringset_destroy()`` from a
``call_rcu()`` callback) so that in-flight readers drain before
the storage is freed.


Implementation
==============

Each stringset is rooted on the following structure::

    struct stringset {
            char         **ss_strings;
            unsigned int   ss_count;
            unsigned int   ss_capacity;
            bool           ss_finalized;
    };

The implementation uses a sorted array of string pointers, providing
O(log N) membership testing and O(N+M) intersection operations.

+----------------------------+-------------+
| Operation                  | Complexity  |
+============================+=============+
| stringset_add              | O(1)        |
+----------------------------+-------------+
| stringset_finalize         | O(N log N)  |
+----------------------------+-------------+
| stringset_is_member        | O(log N)    |
+----------------------------+-------------+
| stringset_intersection     | O(N + M)    |
+----------------------------+-------------+
| stringset_copy             | O(N)        |
+----------------------------+-------------+

API Reference
=============

.. kernel-doc:: include/linux/stringset.h
   :internal:

.. kernel-doc:: lib/stringset.c
   :export:
