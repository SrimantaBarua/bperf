#!/bin/bash

DISK=archmod.qcow2
SMP=2
CDROM=""
SHARED_FOLDER="$PWD/shared_folder/"
#CDROM="-cdrom /home/barua/Downloads/archlinux-2020.09.01-x86_64.iso"

qemu-system-x86_64 \
    -cpu host \
    -enable-kvm \
    -smp $SMP \
    -m 2048 \
    -drive "file=$DISK,media=disk,if=virtio" \
    -net nic -net "user,smb=$SHARED_FOLDER" \
    $CDROM \
    -sdl
