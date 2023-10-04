#!/bin/bash

eval "$(guestfish --listen)"

guestfish --verbose --remote \
    add "${ROOTFS_PATH}" label:img : \
    launch : \
    mount /dev/disk/guestfs/img / : \
    copy-in "${BPF_OBJECTS_PATH}" / : \
    chmod 0755 /bpf_objects

guestfish --remote exit
