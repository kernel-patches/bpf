#!/bin/bash

eval "$(guestfish --listen)"

guestfish --verbose --remote \
    add /tmp/root.img label:img : \
    launch : \
    mount /dev/disk/guestfs/img / : \
    copy-in /tmp/bpf_objects / : \
    chmod 0755 /bpf_objects

guestfish --remote exit
