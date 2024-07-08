#!/bin/bash

set -eu

commit_id="${1}"

# $1 - the SHA-1 to fetch and check out
fetch_and_checkout() {
  local build_base_sha

  build_base_sha="${1}"
  # If cached artifacts became stale for one reason or another, we
  # may not have the build base SHA available. Fetch it and retry.
  git fetch origin "${build_base_sha}" && git checkout --quiet "${build_base_sha}"
}

# $1 - value of KBUILD_OUTPUT
clear_cache_artifacts() {
  local output_dir

  output_dir="${1}"
  echo "Unable to find earlier upstream ref. Discarding KBUILD_OUTPUT contents..."
  rm --recursive --force "${output_dir}"
  mkdir "${output_dir}"
  false
}

# $1 - value of KBUILD_OUTPUT
# $2 - current time in ISO 8601 format
restore_source_code_times() {
  local build_output
  local current_time
  local src_time
  local obj_time

  build_output="${1}"
  current_time="${2}"
  src_time="$(date --iso-8601=ns --date="${current_time} - 2 minutes")"
  obj_time="$(date --iso-8601=ns --date="${current_time} - 1 minute")"

  git ls-files | xargs --max-args=10000 touch -m --no-create --date="${src_time}"
  find "${build_output}" -type f | xargs --max-args=10000 touch -m --no-create --date="${obj_time}"
  git checkout --quiet -
  echo "Adjusted src and obj time stamps relative to system time"
}

mkdir --parents "${KBUILD_OUTPUT}"
current_time="$(date --iso-8601=ns)"

if [ -f "${KBUILD_OUTPUT}/.build-base-sha" ]; then
  build_base_sha="$(cat "${KBUILD_OUTPUT}/.build-base-sha")"
  echo "Setting up base build state for ${build_base_sha}"

  (
    git checkout --quiet "${build_base_sha}" \
      || fetch_and_checkout "${build_base_sha}" \
      || clear_cache_artifacts "${KBUILD_OUTPUT}"
  ) && restore_source_code_times "${KBUILD_OUTPUT}" "${current_time}"
else
  echo "No previous build data found"
fi

echo -n "${commit_id}" > "${KBUILD_OUTPUT}/.build-base-sha"
