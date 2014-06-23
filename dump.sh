#!/bin/bash
set +x

rm -rf dump && mkdir dump

./criu dump  \
    --tcp-established                 \
    -n net -n mnt -n ipc -n pid       \
    --action-script "/home/ubuntu/criu/test/app-emu/lxc/network-script.sh"   \
    -D dump/ -o dump-$$.log \
    -t $(lxc-info -n u1 -p -H) \
    -vvvvvv \
    --file-locks

cat dump/dump-$$.log
