---
# SPDX-License-Identifier: GPL-2.0-only
name: find-siblings
description: >-
  Find other places in the Linux kernel tree that have the same defect as a
  bug being fixed, and verify each candidate. Use after fixing or reviewing
  a bug fix, or when asked whether the same bug exists elsewhere.
---

# Find other instances of a bug

Follow the rules for skills in Documentation/process/coding-assistants.rst.

- State the defect as a rule that does not depend on local names, such as
  "memory from kvmalloc() is released with kfree()".
- Search the tree as it was before the fix, not the working tree. Look at
  other users of the same interface, field or lock, code copied from the same
  origin, the rest of the series that introduced the bug, and earlier fixes
  for the same defect. Limit history searches to the relevant directories.
- If Coccinelle is available (`spatch --version` works), search for the
  defect with a semantic patch as
  [references/coccinelle.md](references/coccinelle.md) describes. Otherwise
  use text searches and report that limit.
- A match is a lead. Read each candidate with its callers, locking and object
  lifetimes, and classify it as confirmed, safe or undetermined, with the
  reason. Check whether a confirmed site is already fixed in the current tree
  or in a pending tree such as linux-next.
- If several sites have the same defect, check whether the interface they use
  invites it, for example by making every caller drop a reference by hand when
  it leaves a loop early. If it does, report that the defect is better fixed
  in the interface, along with the sites. The developer decides which way to
  fix it.

Return the searches you ran and their scope, with any semantic patch you
used, and the classified sites with their maintainers. Do not fix the sites or
the interface.
