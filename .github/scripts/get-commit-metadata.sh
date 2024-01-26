#!/bin/bash

branch="${GITHUB_BASE_REF}"

if [ "${GITHUB_EVENT_NAME}" = 'push' ]; then
  branch="${GITHUB_REF_NAME}"
fi

echo "branch=${branch}" >> "${GITHUB_OUTPUT}"

upstream="${branch//_base/}"
commit="$(
  git rev-parse "origin/${upstream}" &> /dev/null \
    || (
      git fetch --quiet --prune --no-tags --depth=1 --no-recurse-submodules origin "+refs/heads/${upstream}:refs/remotes/origin/${upstream}" && \
      git rev-parse "origin/${upstream}"
    )
)"
timestamp_utc="$(TZ=utc git show --format='%cd' --no-patch --date=iso-strict-local "${commit}")"

echo "timestamp=${timestamp_utc}" >> "${GITHUB_OUTPUT}"
echo "commit=${commit}" >> "${GITHUB_OUTPUT}"
echo "Most recent upstream commit is ${commit}"
