#!/bin/sh

umount /mnt/ramdisk
rmmod nova
insmod nova.ko measure_timing=0

sleep 1

mount -t NOVA -o physaddr=0x200000000,init=8G NOVA /mnt/ramdisk

