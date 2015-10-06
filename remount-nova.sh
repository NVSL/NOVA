#!/bin/sh

echo "Unmount existing partition..."
umount /mnt/ramdisk
rmmod nova
insmod nova.ko measure_timing=0

echo "Unmount done."
sleep 1

echo "Mounting..."
mount -t NOVA -o physaddr=0x200000000 NOVA /mnt/ramdisk

