#!/bin/sh

umount /mnt/ramdisk
rmmod pmfs
rmmod pmem
insmod pmfs.ko measure_timing=0

sleep 1

mount -t pmfs -o physaddr=0x200000000,init=8G CoolFS /mnt/ramdisk

