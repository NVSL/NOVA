# NOVA: NOn-Volatile memory Accelerated log-structured file system

## Introduction
NOVA is a log-structured file system designed for byte-addressable, non-volatile memories. NOVA is fully POSIX compliant so that existing applications need not be modified to run on NOVA. NOVA bypasses the block layer and OS page cache, writes to NVM directly and reduces the software overhead. 

NOVA provides strong data consistency guanrantees:

* Atomic metadata update: each directory operation is atomic.
* Atomic data update; for each `write` operation, the file data and the inode are updated in a transactional way.
* Atomic `msync`: NOVA supports `mmap` operation, and modified data is committed to NVM atomically on each `msync` operation.

With atomicity guarantees, NOVA is able to recover from system failures and restore to a consistent state.

## Building NOVA
NOVA works on x86-64 Linux kernel 4.3, and relies on the NVDIMM support.

To build NOVA, first build up your 64bit 4.3 kernel with NVDIMM support (`CONFIG_BLK_DEV_PMEM`), then build NOVA with a simple

~~~
#make
~~~

command.

## Running NOVA
NOVA runs on a physically contiguous memory region that is not used by the Linux kernel. To reserve the memory space you can boot the kernel with `memmap` command line option. 

For instance, adding `memmap=4G!8G` to the kernel boot parameters will reserve 4GB memory starting from 8GB address, and the kernel will create a `pmem0` block device under the `/dev` directory.

After the OS has booted, you can initialize a NOVA instance with the following command:


~~~
#insmod nova.ko
#mount -t NOVA -o init /dev/pmem0 /mnt/ramdisk 
~~~

The above commands create a NOVA instance on pmem0 device.

To recover an existing NOVA instance, mount NOVA without the init option, for example:

~~~
#mount -t NOVA /dev/pmem0 /mnt/ramdisk 
~~~

There are two scripts provided in the source code, `setup-nova.sh` and `remount-nova.sh` to help setup NOVA.

## Current limitations

* NOVA only works on x86-64 kernels.
* NOVA does not currently support extended attributes or ACL.
* NOVA requires the underlying block device to support DAX (Direct Access) feature.
