#!/bin/bash

DISK=archmod.qcow2
CDROM=""
#CDROM="-cdrom /home/barua/Downloads/archlinux-2020.09.01-x86_64.iso"

qemu-system-x86_64 \
    -cpu host \
    -enable-kvm \
    -m 2048 \
    -nic user,model=virtio \
    -drive "file=$DISK,media=disk,if=virtio" \
    $CDROM \
    -sdl
