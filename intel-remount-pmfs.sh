#!/bin/sh

echo "Unmount existing partition..."
umount /mnt/ramdisk
rmmod pmfs
insmod pmfs.ko measure_timing=0

echo "Unmount done."
sleep 1

echo "Mounting..."

mount -t pmfs -o physaddr=0x10000000000 CoolFS /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
