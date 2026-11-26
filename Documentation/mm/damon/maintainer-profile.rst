.. SPDX-License-Identifier: GPL-2.0

DAMON Maintainer Entry Profile
==============================

The DAMON subsystem covers the files that are listed in 'MEMORY MANAGEMENT -
DAMON' section of 'MAINTAINERS' file.

The mailing lists for the subsystem are damon@lists.linux.dev and
linux-mm@kvack.org.

Non-urgent patches should be made against the damon.git `for-next
<https://git.kernel.org/mm/damon/h/for-next>`_ tree.  Urgent patches should be
made against the damon.git `for-next-fixes
<https://git.kernel.org/mm/damon/h/for-next-fixes>`_ tree.  If there is a
reason to not use those branches as the baseline of the patch, please explain
the reason and what baseline is used.

Patches should be posted to the mailing lists whenever possible.

Submit checklist addendum
-------------------------

When making DAMON changes, you should do below.

- Build changes related outputs including kernel and documents.
- Ensure the builds introduce no new errors or warnings.
- Run and ensure no new failures for DAMON `selftests
  <https://github.com/damonitor/damon-tests/blob/master/corr/run.sh#L49>`_ and
  `kunittests
  <https://github.com/damonitor/damon-tests/blob/master/corr/tests/kunit.sh>`_.

Further doing below and putting the results will be helpful.

- Run `damon-tests/corr
  <https://github.com/damonitor/damon-tests/tree/master/corr>`_ for normal
  changes.
- Measure impacts on benchmarks or real world workloads for performance
  changes.

Key cycle dates
---------------

Patches can be sent to and reviewed on the mailing lists anytime.

Patches that are sufficiently reviewed will be merged into damon.git
``for-next`` or ``for-next-fixes`` trees.  The destination tree is decided
based on the urgency of the patches.  Non-urgent patches are merged into
``for-next``.  Urgent patches are merged into ``for-next-fixes``.  Being merged
into damon.git is only for additional review and testing.  All patches in
damon.git can be reviewed, modified and dropped at any time.

Patches in ``for-next-fixes`` tree stay there for at least one week, for
additional review and testing.  After that, those would be pull-requested to
the mainline.

Patches in ``for-next`` tree stay there at least two weeks, for additional
review and testing.  After that, those would be pull-requested to the mainline,
in the next merge window.

``for-next`` tree is closed for new patches from -rc6 release to next -rc1
release.

Review cadence
--------------

The DAMON maintainer usually works in a flexible way, except early morning in PT
(Pacific Time).  The response to patches will occasionally be slow.  Do not
hesitate to send a ping if you have not heard back within a week of sending a
patch.

Mailing tool
------------

Like many other Linux kernel subsystems, DAMON uses the mailing lists
(damon@lists.linux.dev and linux-mm@kvack.org) as the major communication
channel.  There is a simple tool called `HacKerMaiL
<https://github.com/damonitor/hackermail>`_ (``hkml``), which is for people who
are not very familiar with the mailing lists based communication.  The tool
could be particularly helpful for DAMON community members since it is developed
and maintained by DAMON maintainer.  The tool is also officially announced to
support DAMON and general Linux kernel development workflow.

In other words, `hkml <https://github.com/damonitor/hackermail>`_ is a mailing
tool for DAMON community, which DAMON maintainer is committed to support.
Please feel free to try and report issues or feature requests for the tool to
the maintainer.

Community meetup
----------------

DAMON community has a bi-weekly meetup series for members who prefer
synchronous conversations over mails.  It is for discussions on specific topics
between a group of members including the maintainer.  The maintainer shares the
available time slots, and attendees should reserve one of those at least 24
hours before the time slot, by reaching out to the maintainer.

Schedules and reservation status are available at the Google `doc
<https://docs.google.com/document/d/1v43Kcj3ly4CYqmAkMaZzLiM2GEnWfgdGbZAH3mi2vpM/edit?usp=sharing>`_.
There is also a public Google `calendar
<https://calendar.google.com/calendar/u/0?cid=ZDIwOTA4YTMxNjc2MDQ3NTIyMmUzYTM5ZmQyM2U4NDA0ZGIwZjBiYmJlZGQxNDM0MmY4ZTRjOTE0NjdhZDRiY0Bncm91cC5jYWxlbmRhci5nb29nbGUuY29t>`_
that has the events.  Anyone can subscribe to it.  DAMON maintainer will also
provide periodic reminders to the mailing list (damon@lists.linux.dev).

AI Review
---------

For patches that are publicly posted to DAMON mailing list
(damon@lists.linux.dev), AI reviews of the patches will be available at
sashiko.dev.  The reviews will also be sent as replies to the author of the
patch and the mailing list.

Patch authors are encouraged to check the AI reviews and share their opinions
by replying on the mail thread.  It is only an optional recommendation.  DAMON
maintainer could also ask any question about the AI reviews, though.
