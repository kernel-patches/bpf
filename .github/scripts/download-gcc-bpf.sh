#!/bin/bash

set -euo pipefail

GCC_BPF_RELEASE_GH_REPO=$1
INSTALL_DIR=$(realpath $2)

cd /tmp

if ! command -v gh &> /dev/null; then
    # https://github.com/cli/cli/blob/trunk/docs/install_linux.md
    (type -p wget >/dev/null || (sudo apt update && sudo apt install wget -y)) \
	&& sudo mkdir -p -m 755 /etc/apt/keyrings \
	&& out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
	&& cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& sudo mkdir -p -m 755 /etc/apt/sources.list.d \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
	&& sudo apt update \
	&& sudo apt install gh -y
fi

tag=$(gh release list -L 1 -R ${GCC_BPF_RELEASE_GH_REPO} --json tagName -q .[].tagName)
if [[ -z "$tag" ]]; then
    echo "Could not find latest GCC BPF release at ${GCC_BPF_RELEASE_GH_REPO}"
    exit 1
fi

url="https://github.com/${GCC_BPF_RELEASE_GH_REPO}/releases/download/${tag}/${tag}.tar.zst"
echo "Downloading $url"
wget -q "$url"

tarball=${tag}.tar.zst
dir=$(tar tf $tarball | head -1 || true)

echo "Extracting $tarball ..."
tar -I zstd -xf $tarball && rm -f $tarball

rm -rf $INSTALL_DIR
mv -v $dir $INSTALL_DIR

cd -
