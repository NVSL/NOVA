/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include "pmfs.h"

/* symname is always written at the beginning of log page */
int pmfs_block_symlink(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, const char *symname, int len)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	u64 block;
	char *blockp;

	block = pmfs_extend_inode_log(sb, pi, sih, 0, 1);
	if (block == 0)
		return -ENOMEM;

	blockp = (char *)pmfs_get_block(sb, block);

	if (len >= PAGE_SIZE - 1)
		return -EINVAL;

	pmfs_memunlock_block(sb, blockp);
	__copy_from_user_inatomic_nocache(blockp, symname, len);
	blockp[len] = '\0';
	pmfs_memlock_block(sb, blockp);

	pmfs_update_tail(pi, block + len + 1);
	return 0;
}

static int pmfs_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	char *blockp;

	blockp = (char *)pmfs_get_block(sb, pi->log_head);
	return readlink_copy(buffer, buflen, blockp);
}

static void *pmfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	char *blockp;

	blockp = (char *)pmfs_get_block(sb, pi->log_head);
	nd_set_link(nd, blockp);
	return NULL;
}

const struct inode_operations pmfs_symlink_inode_operations = {
	.readlink	= pmfs_readlink,
	.follow_link	= pmfs_follow_link,
	.setattr	= pmfs_notify_change,
};
