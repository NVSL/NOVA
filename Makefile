#
# Makefile for the linux pmfs-filesystem routines.
#

obj-m += pmfs.o pmem.o

pmfs-y := balloc.o bbuild.o dax.o dir.o file.o inode.o ioctl.o journal.o namei.o stats.o super.o symlink.o wprotect.o

all:
	make -C /media/root/External-Linux/linux-kernel M=`pwd`

running:
	make -C /media/root/New_Volume1/linux-kernel M=`pwd`
	
pmep:
	make -C /root/Andiry/linux-test M=`pwd`
	
clean:
	rm -rf *.o *.mod.c modules.* Module.* *.ko
