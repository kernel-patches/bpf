.. SPDX-License-Identifier: GPL-2.0

Checking for needed translation updates
=======================================

This script helps track the translation status of the documentation in
different locales, i.e., whether the documentation is up-to-date with
the English counterpart.

How it works
------------

The English kernel documentation and its translation use the same relative path
below ``Documentation/`` and ``Documentation/translations/<locale>/``.
For example, ``Documentation/process/foo.rst`` corresponds to
``Documentation/translations/zh_CN/process/foo.rst``. A locale-wide check
starts with English files and reports any without a translation at the
corresponding path. A translated file at a different path is not treated as
its translation. When explicitly checked, the script reports that it cannot
find a same-path English source for such a file. This says nothing about
the accuracy of any existing source-path annotation in that file. The script
does not read ``:Original:`` fields.

The script uses ``git log`` to find the latest English commit corresponding
to the translation and the latest English commit at HEAD. It first checks
the translation commit message for ``update to commit`` or ``Update the
translation through commit`` followed by a 12-character hexadecimal commit
hash. Otherwise, it estimates the source revision by author date. This
includes cases where the translation and English source were initially
merged on different branches, or the named commit is unavailable in the
local Git history. The estimate can be inaccurate, especially when commits
are backdated or the source has moved.
If the two English revisions differ, the script reports the commits to review.

Features implemented

-  check all files in a certain locale
-  check a single file or a set of files
-  select the logging level and log file
-  track the translation status of files that have no translation
-  check files in a directory

Usage
-----

::

   tools/docs/checktransupdate.py --help

Please refer to the output of argument parser for usage details.

Samples

-  ``tools/docs/checktransupdate.py -l zh_CN``
   This checks for updates to zh_CN translations and lists English files
   without a corresponding translation.
-  ``tools/docs/checktransupdate.py Documentation/translations/zh_CN/dev-tools/testing-overview.rst``
   This will only print the status of the specified file.
-  ``tools/docs/checktransupdate.py -l sp_SP``
   This will check Spanish translations at the corresponding paths.
-  ``tools/docs/checktransupdate.py Documentation/translations/it_IT/process``
   This will check translated files under the directory.

Then the output is something like:

::

    Documentation/dev-tools/kfence.rst
    No translation in the locale of zh_CN

    Documentation/translations/zh_CN/dev-tools/testing-overview.rst
    commit 42fb9cfd5b18 ("Documentation: dev-tools: Add link to RV docs")
    1 commits needs resolving in total

The script stops at the first translated file it cannot check and exits with
a nonzero status.
It does not determine whether the translated text fully reflects the English
source; review the reported commits and the files themselves.
