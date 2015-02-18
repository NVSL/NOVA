#
# Makefile for the linux pmfs-filesystem routines.
#

obj-m += pmfs.o

pmfs-y := bbuild.o balloc.o dir.o file.o inode.o namei.o super.o symlink.o ioctl.o journal.o cache.o pmfs_stats.o xip.o wprotect.o

all:
	make -C /media/root/New_Volume1/Linux-pmfs M=`pwd`

running:
	make -C /media/root/New_Volume1/linux-kernel M=`pwd`
	
clean:
	rm -rf *.o *.mod.c modules.* Module.* *.ko
