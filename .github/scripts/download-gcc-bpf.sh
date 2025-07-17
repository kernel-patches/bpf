#!/bin/bash

set -euo pipefail

GCC_BPF_RELEASE_GH_REPO=$1
INSTALL_DIR=$(realpath $2)

cd /tmp

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

