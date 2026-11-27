---
# SPDX-License-Identifier: GPL-2.0-only
name: find-fixes
description: >-
  Determine the bug-introducing commit and return a verified Fixes tag for
  a Linux kernel fix. Use when preparing or reviewing bug-fix patches,
  drafting their commit messages, or checking an existing Fixes tag.
---

# Determine a Fixes tag

Read the description of the Fixes: tag in
Documentation/process/submitting-patches.rst. It says which commit to name
and how to format the tag. Follow the rules for skills in
Documentation/process/coding-assistants.rst.

- First establish exactly which bug the fix addresses: the failure, how it is
  triggered and the code involved. Trace only that bug. If the search leads
  to a different bug or subsystem, go back to the fix.
- Name a commit from the history of the tree the fix applies to. A stable
  backport of that commit, or a commit that exists only on another branch, is
  not a valid tag.
- Treat blame output, an existing Fixes tag and a bisection result as leads,
  not answers. Follow the code back through moves, renames, file splits and
  older implementations to the commit that made it wrong.
- For each candidate, compare the commit with its parent and explain why the
  code was correct before and wrong after. Keep apart the commit that added
  the code, the commit that made it wrong, and a later commit that only made
  the bug reachable, which gets a tag of its own.
- Check each parent of a merge, whether the bug was reverted and later
  reintroduced, and whether a backport differs from its upstream commit.
- If the bug is already present in the first commit of the Git history, name
  that commit: Fixes: 1da177e4c3f4 ("Linux-2.6.12-rc2"). Confirm that the bug
  exists there instead of using it as a default. A shallow clone boundary is
  not an introducing commit; report the limit instead.

Take the commit ID and subject from the commit itself instead of typing them.
Return the tags with that explanation and the candidates you rejected. If the
origin cannot be established, return no tag and say what is missing.
