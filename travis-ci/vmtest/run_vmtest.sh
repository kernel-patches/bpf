#!/bin/bash

set -eu

source $(cd $(dirname $0) && pwd)/helpers.sh
VMTEST_SETUPCMD="GITHUB_WORKFLOW=${GITHUB_WORKFLOW:-} PROJECT_NAME=${PROJECT_NAME} ./${PROJECT_NAME}/travis-ci/vmtest/run_selftests.sh"
echo "KERNEL: $KERNEL"
echo

${VMTEST_ROOT}/build_pahole.sh travis-ci/vmtest/pahole

# Install required packages
travis_fold start install_clang "Installing Clang/LLVM"
sudo apt-get install --allow-downgrades -y libc6=2.31-0ubuntu9.2
sudo aptitude install -y g++ libelf-dev
n=0
while [ $n -lt 5 ]; do
  set +e && \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add - && \
  echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal main" | sudo tee -a /etc/apt/sources.list && \
  sudo apt-get update && \
  sudo aptitude -y install clang-14 lld-14 llvm-14 && \
  set -e && \
  break
  n=$(($n + 1))
done
if [ $n -ge 5 ] ; then
  echo "clang install failed"
  exit 1
fi
travis_fold end install_clang

# Build selftests (and latest kernel, if necessary)
KERNEL="${KERNEL}" ${VMTEST_ROOT}/prepare_selftests.sh

travis_fold start adduser_to_kvm "Add user ${USER}"
sudo adduser "${USER}" kvm
travis_fold stop adduser_to_kvm

# Escape whitespace characters.
setup_cmd=$(sed 's/\([[:space:]]\)/\\\1/g' <<< "${VMTEST_SETUPCMD}")

if [[ "${KERNEL}" = 'LATEST' ]]; then
  sudo -E sudo -E -u "${USER}" "${VMTEST_ROOT}/run.sh" -b "${REPO_ROOT}"  -o -d ~ -s "${setup_cmd}" ~/root.img;
else
  sudo -E sudo -E -u "${USER}" "${VMTEST_ROOT}/run.sh" -k "${KERNEL}*" -o -d ~ -s "${setup_cmd}" ~/root.img;
fi
