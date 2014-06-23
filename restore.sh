#!/bin/bash

./criu restore \
    -D dump/ \
    -vvvvvv \
    --file-locks \
    --action-script "/home/ubuntu/criu/test/app-emu/lxc/network-script.sh"   \
    -n net -n mnt -n ipc -n pid \
    --tcp-established \
    2>&1 | tee dump/restore.log
