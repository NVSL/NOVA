#
# Makefile for the linux NOVA filesystem routines.
#

obj-m += nova.o

nova-y := balloc.o bbuild.o dax.o dir.o file.o inode.o ioctl.o journal.o namei.o stats.o super.o symlink.o wprotect.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

clean:
	rm -rf *.o *.mod.c modules.* Module.* *.ko
