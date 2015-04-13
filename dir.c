/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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
#include <linux/pagemap.h>
#include "pmfs.h"

/*
 *	Parent is locked.
 */

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

static int pmfs_add_dirent_to_buf(pmfs_transaction_t *trans,
	struct dentry *dentry, struct inode *inode,
	struct pmfs_direntry *de, u8 *blk_base,  struct pmfs_inode *pidir)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	unsigned short reclen;
	int nlen, rlen;
	u64 curr_entry;
	char *top;

	reclen = PMFS_DIR_REC_LEN(namelen);
	if (!de) {
		de = (struct pmfs_direntry *)blk_base;
		top = blk_base + dir->i_sb->s_blocksize - reclen;
		while ((char *)de <= top) {
#if 0
			if (!pmfs_check_dir_entry("pmfs_add_dirent_to_buf",
			    dir, de, blk_base, offset))
				return -EIO;
			if (pmfs_match(namelen, name, de))
				return -EEXIST;
#endif
			rlen = le16_to_cpu(de->de_len);
			if (de->ino) {
				nlen = PMFS_DIR_REC_LEN(de->name_len);
				if ((rlen - nlen) >= reclen)
					break;
			} else if (rlen >= reclen)
				break;
			de = (struct pmfs_direntry *)((char *)de + rlen);
		}
		if ((char *)de > top)
			return -ENOSPC;
	}
	rlen = le16_to_cpu(de->de_len);

	if (de->ino) {
		struct pmfs_direntry *de1;
//		pmfs_add_logentry(dir->i_sb, trans, &de->de_len,
//			sizeof(de->de_len), LE_DATA);
		nlen = PMFS_DIR_REC_LEN(de->name_len);
		de1 = (struct pmfs_direntry *)((char *)de + nlen);
//		pmfs_memunlock_block(dir->i_sb, blk_base);
		de1->de_len = cpu_to_le16(rlen - nlen);
		de->de_len = cpu_to_le16(nlen);
//		pmfs_memlock_block(dir->i_sb, blk_base);
		de = de1;
	} else {
//		pmfs_add_logentry(dir->i_sb, trans, &de->ino,
//			sizeof(de->ino), LE_DATA);
	}
//	pmfs_memunlock_block(dir->i_sb, blk_base);
	/*de->file_type = 0;*/
	if (inode) {
		de->ino = cpu_to_le64(inode->i_ino);
		/*de->file_type = IF2DT(inode->i_mode); */
	} else {
		de->ino = 0;
	}
	de->name_len = namelen;
	memcpy(de->name, name, namelen);
//	pmfs_memlock_block(dir->i_sb, blk_base);
//	pmfs_flush_buffer(de, reclen, false);
	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	/*dir->i_version++; */

	pmfs_memunlock_inode(dir->i_sb, pidir);
	pidir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	pidir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
	pmfs_memlock_inode(dir->i_sb, pidir);

	curr_entry = pmfs_append_dir_inode_entry(sb, pidir, dir, de, reclen);
	/* FIXME: Flush all data before update log_tail */
	pidir->log_tail = curr_entry + reclen;

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int pmfs_add_entry(pmfs_transaction_t *trans, struct dentry *dentry,
		struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	int retval = -EINVAL;
	unsigned long block, blocks;
	struct pmfs_direntry *de;
	char *blk_base;
	struct pmfs_inode *pidir;

	if (!dentry->d_name.len)
		return -EINVAL;

	pidir = pmfs_get_inode(sb, dir->i_ino);
	pmfs_add_logentry(sb, trans, pidir, MAX_DATA_PER_LENTRY, LE_DATA);

	blocks = dir->i_size >> sb->s_blocksize_bits;
	for (block = 0; block < blocks; block++) {
		blk_base = (char *)pmfs_find_dir_block(dir, block);
		if (!blk_base) {
			retval = -EIO;
			goto out;
		}
		retval = pmfs_add_dirent_to_buf(trans, dentry, inode,
				NULL, blk_base, pidir);
		if (retval != -ENOSPC)
			goto out;
	}
	retval = pmfs_alloc_dir_blocks(dir, blocks, 1, false);
	if (retval)
		goto out;

	dir->i_size += dir->i_sb->s_blocksize;
	pmfs_update_isize(dir, pidir);

	blk_base = (char *)pmfs_find_dir_block(dir, blocks);
	if (!blk_base) {
		retval = -ENOSPC;
		goto out;
	}
	/* No need to log the changes to this de because its a new block */
	de = (struct pmfs_direntry *)blk_base;
//	pmfs_memunlock_block(sb, blk_base);
	de->ino = 0;
	de->de_len = cpu_to_le16(sb->s_blocksize);
//	pmfs_memlock_block(sb, blk_base);
	/* Since this is a new block, no need to log changes to this block */
	retval = pmfs_add_dirent_to_buf(NULL, dentry, inode, de, blk_base,
		pidir);
out:
	return retval;
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int pmfs_remove_entry(pmfs_transaction_t *trans, struct dentry *de,
		struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct inode *dir = de->d_parent->d_inode;
	struct pmfs_inode *pidir;
	struct qstr *entry = &de->d_name;
	struct pmfs_direntry *res_entry, *prev_entry;
	struct pmfs_direntry de_entry;
	unsigned short de_len;
	u64 curr_entry;
	int retval = -EINVAL;
	unsigned long blocks, block;
	char *blk_base = NULL;

	if (!de->d_name.len)
		return -EINVAL;

	blocks = dir->i_size >> sb->s_blocksize_bits;

	for (block = 0; block < blocks; block++) {
		blk_base = (char *)pmfs_find_dir_block(dir, block);
		if (!blk_base)
			goto out;
		if (pmfs_search_dirblock(blk_base, dir, entry,
					  block << sb->s_blocksize_bits,
					  &res_entry, &prev_entry) == 1)
			break;
	}

	if (block == blocks)
		goto out;
	if (prev_entry) {
//		pmfs_add_logentry(sb, trans, &prev_entry->de_len,
//				sizeof(prev_entry->de_len), LE_DATA);
//		pmfs_memunlock_block(sb, blk_base);
		prev_entry->de_len =
			cpu_to_le16(le16_to_cpu(prev_entry->de_len) +
				    le16_to_cpu(res_entry->de_len));
//		pmfs_memlock_block(sb, blk_base);
	} else {
//		pmfs_add_logentry(sb, trans, &res_entry->ino,
//				sizeof(res_entry->ino), LE_DATA);
//		pmfs_memunlock_block(sb, blk_base);
		res_entry->ino = 0;
//		pmfs_memlock_block(sb, blk_base);
	}
	/*dir->i_version++; */
	dir->i_ctime = dir->i_mtime = CURRENT_TIME_SEC;

	pidir = pmfs_get_inode(sb, dir->i_ino);
	pmfs_add_logentry(sb, trans, pidir, MAX_DATA_PER_LENTRY, LE_DATA);

	pmfs_memunlock_inode(sb, pidir);
	pidir->i_mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	pidir->i_ctime = cpu_to_le32(dir->i_ctime.tv_sec);
	pmfs_memlock_inode(sb, pidir);

	/* Append a zero-length entry for deletion */
	de_len = PMFS_DIR_REC_LEN(0);
	de_entry.ino = inode->i_ino;
	de_entry.de_len = de_len;
	de_entry.name_len = 0;
	de_entry.file_type = 0;
	curr_entry = pmfs_append_dir_inode_entry(sb, pidir, dir,
					&de_entry, de_len);
	/* FIXME: Flush all data before update log_tail */
	pidir->log_tail = curr_entry + de_len;
	retval = 0;
out:
	return retval;
}

static int pmfs_replay_add_dirent_to_buf(struct super_block *sb,
	struct pmfs_inode *pi, struct inode *inode,
	struct pmfs_direntry *entry, struct pmfs_direntry *de,
	u8 *blk_base)
{
	const char *name = entry->name;
	int namelen = entry->name_len;
	unsigned short reclen;
	int nlen, rlen;
	char *top;

	reclen = PMFS_DIR_REC_LEN(namelen);
	if (!de) {
		de = (struct pmfs_direntry *)blk_base;
		top = blk_base + sb->s_blocksize - reclen;
		while ((char *)de <= top) {
			rlen = le16_to_cpu(de->de_len);
			if (de->ino) {
				nlen = PMFS_DIR_REC_LEN(de->name_len);
				if ((rlen - nlen) >= reclen)
					break;
			} else if (rlen >= reclen)
				break;
			de = (struct pmfs_direntry *)((char *)de + rlen);
		}
		if ((char *)de > top)
			return -ENOSPC;
	}
	rlen = le16_to_cpu(de->de_len);

	if (de->ino) {
		struct pmfs_direntry *de1;
		nlen = PMFS_DIR_REC_LEN(de->name_len);
		de1 = (struct pmfs_direntry *)((char *)de + nlen);
		de1->de_len = cpu_to_le16(rlen - nlen);
		de->de_len = cpu_to_le16(nlen);
		de = de1;
	}
	/*de->file_type = 0;*/
	de->ino = entry->ino;
	de->name_len = namelen;
	memcpy(de->name, name, namelen);

	return 0;
}

int pmfs_replay_add_entry(struct super_block *sb, struct pmfs_inode *pi,
		struct inode *inode, struct pmfs_direntry *entry)
{
	int retval = -EINVAL;
	unsigned long block, blocks;
	char *blk_base;

	if (!entry->name_len)
		return -EINVAL;

	blocks = pi->i_size >> sb->s_blocksize_bits;
	for (block = 0; block < blocks; block++) {
		blk_base = (char *)pmfs_find_dir_block(inode, block);
		if (!blk_base) {
			retval = -EIO;
			goto out;
		}

		retval = pmfs_replay_add_dirent_to_buf(sb, pi, inode, entry,
				NULL, blk_base);
		if (retval != -ENOSPC)
			goto out;
	}
	retval = -EIO;
out:
	return retval;
}

int pmfs_replay_remove_entry(struct super_block *sb, struct pmfs_inode *pi,
		struct inode *inode, struct pmfs_direntry *entry)
{
	struct pmfs_direntry *res_entry, *prev_entry;
	int retval = -EINVAL;
	unsigned long blocks, block;
	char *blk_base = NULL;

	blocks = pi->i_size >> sb->s_blocksize_bits;

	for (block = 0; block < blocks; block++) {
		blk_base = (char *)pmfs_find_dir_block(inode, block);
		if (!blk_base)
			goto out;
		if (pmfs_search_dirblock_inode(blk_base, inode, entry,
					  block << sb->s_blocksize_bits,
					  &res_entry, &prev_entry) == 1)
			break;
	}

	if (block == blocks)
		goto out;
	if (prev_entry) {
		prev_entry->de_len =
			cpu_to_le16(le16_to_cpu(prev_entry->de_len) +
				    le16_to_cpu(res_entry->de_len));
	} else {
		res_entry->ino = 0;
	}
	retval = 0;
out:
	return retval;
}

int pmfs_rebuild_dir_inode_tree(struct super_block *sb, struct inode *inode,
			struct pmfs_inode *pi)
{
	struct pmfs_direntry *entry, *de;
	unsigned long block, blocks;
	u64 curr_p = pi->log_head;
	int ret;

	pmfs_dbg("Rebuild dir %lu tree\n", inode->i_ino);
	/*
	 * We will regenerate the tree during blocks assignment.
	 * Set height to 0.
	 */
	pi->height = 0;
	blocks = pi->i_size >> sb->s_blocksize_bits;
	ret = pmfs_alloc_dir_blocks(inode, 0, blocks, false);
	if (ret)
		return ret;

	/* Insert bogus entries for all the blocks */
	for (block = 0; block < blocks; block++) {
		de = (struct pmfs_direntry *)pmfs_find_dir_block(inode, block);
		de->ino = 0;
		de->de_len = cpu_to_le16(sb->s_blocksize);
	}

	while (curr_p != pi->log_tail) {
		if (curr_p == 0) {
			pmfs_err(sb, "log is NULL!\n");
			BUG();
		}

		if (is_last_dir_entry(sb, curr_p))
			curr_p = next_log_page(sb, curr_p);

		pmfs_dbg_verbose("curr_p: 0x%llx\n", curr_p);
		entry = (struct pmfs_direntry *)pmfs_get_block(sb, curr_p);
		pmfs_dbg_verbose("entry @%p, ino %llu, name %s, namelen %u\n",
			entry, entry->ino, entry->name, entry->name_len);

		if (entry->name_len > 0) {
			/* A valid entry to add */
			ret = pmfs_replay_add_entry(sb, pi, inode, entry);
		} else {
			/* Delete the entry */
			ret = pmfs_replay_remove_entry(sb, pi, inode, entry);
		}
		curr_p += entry->de_len;
		if (ret)
			pmfs_err(sb, "ERROR %d\n", ret);
	}

	return 0;
}

void pmfs_rebuild_root_dir(struct super_block *sb, struct pmfs_inode *root_pi)
{
	struct inode inode;

	/* Use a bogus inode to rebuild the root directory */
	inode.i_sb = sb;
	inode.i_ino = PMFS_ROOT_INO;
	pmfs_rebuild_dir_inode_tree(sb, &inode, root_pi);
}

static int pmfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi, *pidir;
	char *blk_base;
	unsigned long offset;
	struct pmfs_direntry *de;
	ino_t ino;

	pidir = pmfs_get_inode(sb, inode->i_ino);
	pmfs_dbg_verbose("%s: ino %llu, root 0x%llx, size %llu\n",
				__func__, (u64)inode->i_ino, pidir->root,
				pidir->i_size);
	if (pidir->root == 0 && pidir->i_size > 0 && S_ISDIR(inode->i_mode))
		pmfs_rebuild_dir_inode_tree(sb, inode, pidir);

	offset = ctx->pos & (sb->s_blocksize - 1);
	while (ctx->pos < inode->i_size) {
		unsigned long blk = ctx->pos >> sb->s_blocksize_bits;

		blk_base = (char *)pmfs_find_dir_block(inode, blk);
		if (!blk_base) {
			pmfs_dbg("directory %lu contains a hole at offset %lld\n",
				inode->i_ino, ctx->pos);
			ctx->pos += sb->s_blocksize - offset;
			continue;
		}
#if 0
		if (file->f_version != inode->i_version) {
			for (i = 0; i < sb->s_blocksize && i < offset; ) {
				de = (struct pmfs_direntry *)(blk_base + i);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (le16_to_cpu(de->de_len) <
				    PMFS_DIR_REC_LEN(1))
					break;
				i += le16_to_cpu(de->de_len);
			}
			offset = i;
			ctx->pos =
				(ctx->pos & ~(sb->s_blocksize - 1)) | offset;
			file->f_version = inode->i_version;
		}
#endif
		while (ctx->pos < inode->i_size
		       && offset < sb->s_blocksize) {
			de = (struct pmfs_direntry *)(blk_base + offset);
			if (!pmfs_check_dir_entry("pmfs_readdir", inode, de,
						   blk_base, offset)) {
				/* On error, skip to the next block. */
				ctx->pos = ALIGN(ctx->pos, sb->s_blocksize);
				break;
			}
			offset += le16_to_cpu(de->de_len);
			if (de->ino) {
				ino = le64_to_cpu(de->ino);
				pi = pmfs_get_inode(sb, ino);
				pmfs_dbg_verbose("ctx: ino %llu, name %s, "
					"name_len %u, de_len %u\n",
					(u64)ino, de->name, de->name_len,
					de->de_len);
				if (!dir_emit(ctx, de->name, de->name_len,
					ino, IF2DT(le16_to_cpu(pi->i_mode))))
					return 0;
			}
			ctx->pos += le16_to_cpu(de->de_len);
		}
		offset = 0;
	}
	return 0;
}

const struct file_operations pmfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= pmfs_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = pmfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pmfs_compat_ioctl,
#endif
};
