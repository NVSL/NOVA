#!/bin/sh

echo "Unmount existing partition..."
umount /mnt/ramdisk
rmmod pmfs
insmod pmfs.ko measure_timing=0

echo "Unmount done."
sleep 1

echo "Mounting..."
mount -t pmfs -o physaddr=0x200000000 CoolFS /mnt/ramdisk

