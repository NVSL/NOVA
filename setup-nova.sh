#!/bin/sh

umount /mnt/ramdisk
rmmod nova
insmod nova.ko measure_timing=0

sleep 1

mount -t NOVA -o init /dev/pmem0 /mnt/ramdisk

