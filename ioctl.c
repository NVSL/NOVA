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

long pmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct pmfs_inode *pi;
	struct super_block *sb = inode->i_sb;
	unsigned int flags;
	u64 new_tail = 0;
	int ret;

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

		pmfs_memunlock_inode(sb, pi);
		ret = pmfs_append_link_change_entry(sb, pi, inode, 0,
							&new_tail);
		if (!ret)
			pmfs_update_tail(pi, new_tail);
		pmfs_memlock_inode(sb, pi);
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
		inode->i_ctime = CURRENT_TIME_SEC;
		inode->i_generation = generation;

		pmfs_memunlock_inode(sb, pi);
		ret = pmfs_append_link_change_entry(sb, pi, inode, 0,
							&new_tail);
		if (!ret)
			pmfs_update_tail(pi, new_tail);
		pmfs_memlock_inode(sb, pi);
		mutex_unlock(&inode->i_mutex);
setversion_out:
		mnt_drop_write_file(filp);
		return ret;
	}
	case PMFS_PRINT_TIMING: {
		pmfs_print_timing_stats(sb);
		return 0;
	}
	case PMFS_CLEAR_STATS: {
		pmfs_clear_stats();
		return 0;
	}
	case PMFS_PRINT_LOG: {
		pmfs_print_inode_log(sb, inode);
		return 0;
	}
	case PMFS_PRINT_LOG_PAGES: {
		pmfs_print_inode_log_pages(sb, inode);
		return 0;
	}
	case PMFS_PRINT_FREE_LISTS: {
		pmfs_print_free_lists(sb);
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
