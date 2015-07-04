/*
 * BRIEF DESCRIPTION
 *
 * Ioctl operations.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2010-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/capability.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include "pmfs.h"

struct sync_range
{
	off_t	offset;
	size_t	length;
};

struct write_request
{
	char*	buf;
	loff_t	offset;
	size_t	len;
};

struct malloc_request
{
	int	category;
	int	size;
};

void pmfs_malloc_test(struct super_block *sb, int category, int size)
{
	timing_t malloc_time;
	int i;
	struct page *page;
	int pfn;
	int check = 1;
	unsigned long *addr = kmalloc(size * sizeof(unsigned long),
					GFP_KERNEL);
	unsigned long flags = GFP_KERNEL;
	void *page_addr;

	PMFS_START_TIMING(malloc_test_t, malloc_time);
	for (i = 0; i < size; i++) {
		switch(category) {
		case TEST_ZERO:
			addr[i] = get_zeroed_page(flags);
			page = virt_to_page((void *)addr[i]);
			pfn = page_to_pfn(page);
//			pmfs_dbg("get_zero_page: page %p pfn %d\n", page, pfn);
			break;
		case TEST_NORMAL:
			addr[i] = __get_free_page(flags);
			page = virt_to_page((void *)addr[i]);
			pfn = page_to_pfn(page);
//			pmfs_dbg("get_free_page: page %p pfn %d\n", page, pfn);
			break;
		case TEST_VMALLOC:
			addr[i] = (unsigned long)vmalloc(PAGE_SIZE);
			page = vmalloc_to_page((void *)addr[i]);
			pfn = page_to_pfn(page);
//			pmfs_dbg("vmalloc: page %p pfn %d\n", page, pfn);
			break;
		case TEST_KMALLOC:
			addr[i] = (unsigned long)kmalloc(PAGE_SIZE, flags);
			page = virt_to_page((void *)addr[i]);
			pfn = page_to_pfn(page);
//			pmfs_dbg("kmalloc: page %p pfn %d\n", page, pfn);
			break;
		case TEST_KZALLOC:
			addr[i] = (unsigned long)kzalloc(PAGE_SIZE, flags);
			page = virt_to_page((void *)addr[i]);
			pfn = page_to_pfn(page);
//			pmfs_dbg("kzalloc: page %p pfn %d\n", page, pfn);
			break;
		case TEST_PAGEALLOC:
			addr[i] = (unsigned long)alloc_page(flags);
			page_addr = kmap_atomic((struct page *)addr[i]);
//			*(unsigned long *)page_addr = 1;
//			pmfs_dbg("alloc page: 0x%lx\n", (unsigned long)page_addr);
			kunmap_atomic(page_addr);
			check = 0;
			break;
		case TEST_PAGEZALLOC:
			flags |= __GFP_ZERO;
			addr[i] = (unsigned long)alloc_page(flags);
			page_addr = kmap_atomic((struct page *)addr[i]);
//			*(unsigned long *)page_addr = 1;
//			pmfs_dbg("alloc page: 0x%lx\n", (unsigned long)page_addr);
			kunmap_atomic(page_addr);
			check = 0;
			break;
		default:
			break;
		}
		if (addr[i] == 0 || (check && addr[i] != DRAM_ADDR(addr[i])))
			pmfs_dbg("Error: page %d addr 0x%lx\n", i, addr[i]);
	}
	PMFS_END_TIMING(malloc_test_t, malloc_time);

	for (i = 0; i < size; i++) {
		pte_t *ptep;
		int dirty;

		dirty = pmfs_is_page_dirty(current->active_mm,
				(unsigned long)addr[i],	&ptep, category);
		if (dirty)
			pmfs_dbg("page 0x%lx is dirty\n",
					(unsigned long)addr[i]);

		switch(category) {
		case TEST_ZERO:
		case TEST_NORMAL:
			free_page(addr[i]);
			break;
		case TEST_VMALLOC:
			vfree((void *)addr[i]);
			break;
		case TEST_KMALLOC:
		case TEST_KZALLOC:
			kfree((void *)addr[i]);
			break;
		case TEST_PAGEALLOC:
		case TEST_PAGEZALLOC:
			__free_page((struct page *)addr[i]);
			break;
		default:
			break;
		}
	}
	kfree(addr);
}

long pmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct pmfs_inode *pi;
	struct super_block *sb = inode->i_sb;
	unsigned int flags;
	int ret;
	pmfs_transaction_t *trans;

	pi = pmfs_get_inode(sb, inode);
	if (!pi)
		return -EACCES;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = le32_to_cpu(pi->i_flags) & PMFS_FL_USER_VISIBLE;
		return put_user(flags, (int __user *)arg);
	case FS_IOC_SETFLAGS: {
		unsigned int oldflags;

		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EPERM;
			goto flags_out;
		}

		if (get_user(flags, (int __user *)arg)) {
			ret = -EFAULT;
			goto flags_out;
		}

		mutex_lock(&inode->i_mutex);
		oldflags = le32_to_cpu(pi->i_flags);

		if ((flags ^ oldflags) &
		    (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				mutex_unlock(&inode->i_mutex);
				ret = -EPERM;
				goto flags_out;
			}
		}

		if (!S_ISDIR(inode->i_mode))
			flags &= ~FS_DIRSYNC_FL;

		flags = flags & FS_FL_USER_MODIFIABLE;
		flags |= oldflags & ~FS_FL_USER_MODIFIABLE;
		inode->i_ctime = CURRENT_TIME_SEC;
		pmfs_set_inode_flags(inode, pi, flags);
		trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}
		pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);
		pmfs_memunlock_inode(sb, pi);
		pi->i_flags = cpu_to_le32(flags);
		pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
		pmfs_memlock_inode(sb, pi);
		pmfs_commit_transaction(sb, trans);
out:
		mutex_unlock(&inode->i_mutex);
flags_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case FS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	case FS_IOC_SETVERSION: {
		__u32 generation;
		if (!inode_owner_or_capable(inode))
			return -EPERM;
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;
		if (get_user(generation, (int __user *)arg)) {
			ret = -EFAULT;
			goto setversion_out;
		}
		mutex_lock(&inode->i_mutex);
		trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			goto out;
		}
		pmfs_add_logentry(sb, trans, pi, sizeof(*pi), LE_DATA);
		inode->i_ctime = CURRENT_TIME_SEC;
		inode->i_generation = generation;
		pmfs_memunlock_inode(sb, pi);
		pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
		pi->i_generation = cpu_to_le32(inode->i_generation);
		pmfs_memlock_inode(sb, pi);
		pmfs_commit_transaction(sb, trans);
		mutex_unlock(&inode->i_mutex);
setversion_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case FS_PMFS_FSYNC: {
		struct sync_range packet;
		copy_from_user(&packet, (void *)arg, sizeof(struct sync_range));
		pmfs_fsync(filp, packet.offset, packet.offset + packet.length, 1);
		return 0;
	}
	case PMFS_PRINT_TIMING: {
		pmfs_print_timing_stats(sb);
		return 0;
	}
	case PMFS_CLEAR_STATS: {
		pmfs_clear_stats();
		return 0;
	}
	case PMFS_COW_WRITE: {
		struct write_request request;
		copy_from_user(&request, (void *)arg,
					sizeof(struct write_request));
		pmfs_cow_file_write(filp, request.buf, request.len,
					&request.offset, true);
		return 0;
	}
	case PMFS_PRINT_LOG: {
		pmfs_print_inode_log(sb, inode);
		return 0;
	}
	case PMFS_PRINT_LOG_PAGE: {
		pmfs_print_inode_log_page(sb, inode);
		return 0;
	}
	case PMFS_PRINT_LOG_BLOCKNODE: {
		pmfs_print_inode_log_blocknode(sb, inode);
		return 0;
	}
	case PMFS_MALLOC_TEST: {
		struct malloc_request request;
		copy_from_user(&request, (void *)arg,
					sizeof(struct malloc_request));
		pmfs_malloc_test(sb, request.category, request.size);
		return 0;
	}
	case PMFS_TEST_MULTITHREAD_RECOVERY: {
		int multithread;
		copy_from_user(&multithread, (void *)arg,
					sizeof(int));
		pmfs_inode_log_recovery(sb, multithread);
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long pmfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case FS_IOC32_SETVERSION:
		cmd = FS_IOC_SETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return pmfs_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif
