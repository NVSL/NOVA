/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
 *
 * Copyright 2015 NVSL, UC San Diego
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
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "nova.h"

unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[NOVA_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

void nova_print_inode_entry(struct nova_file_write_entry *entry)
{
	nova_dbg("entry @%p: pgoff %u, num_pages %u, block 0x%llx, "
		"size %llu\n", entry, entry->pgoff, entry->num_pages,
		entry->block, entry->size);
}

static int nova_init_inode_inuse_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *range_node;

	range_node = nova_alloc_inode_node(sb);
	if (range_node == NULL)
		return -ENOMEM;
	range_node->range_low = 0;
	range_node->range_high = NOVA_NORMAL_INODE_START - 1;
	nova_insert_inodetree(sbi, range_node);
	sbi->num_range_node_inode = 1;
	sbi->s_inodes_used_count = NOVA_NORMAL_INODE_START;
	sbi->first_inode_range = range_node;

	return 0;
}

/* Initialize the inode table. The nova_inode struct corresponding to the
 * inode table has already been zero'd out */
int nova_init_inode_table(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_table(sb);

	nova_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;

	/*
	 * Now inodes are resided in dir logs, and inode_table is
	 * only used to save inodes on umount
	 */
	pi->i_blk_type = NOVA_BLOCK_TYPE_4K;

	return nova_init_inode_inuse_list(sb);
}

static inline void nova_free_contiguous_blocks(struct super_block *sb,
	struct nova_file_write_entry *entry, unsigned long pgoff,
	unsigned long *start_blocknr, unsigned long *num_free,
	unsigned int btype)
{
	unsigned long nvmm;

	entry->invalid_pages++;
	nvmm = get_nvmm(sb, entry, pgoff);

	if (*start_blocknr == 0) {
		*start_blocknr = nvmm;
		*num_free = 1;
	} else {
		if (nvmm == *start_blocknr + *num_free) {
			(*num_free)++;
		} else {
			/* A new start */
			nova_free_data_blocks(sb, *start_blocknr,
						*num_free, btype);
			*start_blocknr = nvmm;
			*num_free = 1;
		}
	}
}

static int nova_delete_cache_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, unsigned int btype)
{
	unsigned long addr;
	unsigned long i;
	void *ret;

	for (i = start_blocknr; i <= last_blocknr; i++) {
		addr = (unsigned long)radix_tree_lookup(&sih->cache_tree, i);
		if (addr) {
			ret = radix_tree_delete(&sih->cache_tree, i);
			nova_free_data_blocks(sb, addr >> PAGE_SHIFT,
							1, btype);
			sih->mmap_pages--;
		}
	}

	return 0;
}

static int nova_delete_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	bool delete_nvmm)
{
	struct nova_file_write_entry *entry;
	struct nova_inode *pi;
	unsigned long free_blocknr = 0, num_free = 0;
	unsigned long last_blocknr;
	unsigned long pgoff = start_blocknr;
	unsigned int btype;
	unsigned int data_bits;
	timing_t delete_time;
	int freed = 0;
	void *ret;

	pi = (struct nova_inode *)nova_get_block(sb, sih->pi_addr);
	btype = pi->i_blk_type;
	data_bits = blk_type_to_shift[btype];

	NOVA_START_TIMING(delete_file_tree_t, delete_time);

	if (sih->i_size == 0)
		goto out;

	last_blocknr = (sih->i_size - 1) >> data_bits;
	if (sih->mmap_pages)
		nova_delete_cache_tree(sb, sih, start_blocknr,
						last_blocknr, btype);

	for (pgoff = start_blocknr; pgoff <= last_blocknr; pgoff++) {
		entry = radix_tree_lookup(&sih->tree, pgoff);
		if (entry) {
			ret = radix_tree_delete(&sih->tree, pgoff);
			BUG_ON(!ret || ret != entry);
			if (delete_nvmm)
				nova_free_contiguous_blocks(sb, entry, pgoff,
					&free_blocknr, &num_free, btype);
			freed++;
		}
	}

	if (free_blocknr)
		nova_free_data_blocks(sb, free_blocknr, num_free, btype);
out:
	NOVA_END_TIMING(delete_file_tree_t, delete_time);
	return freed;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void nova_truncate_file_blocks(struct inode *inode, loff_t start,
				    loff_t end)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	int freed = 0;

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;

	nova_dbg_verbose("truncate: pi %p iblocks %llx %llx %llx %llx\n", pi,
			 pi->i_blocks, start, end, pi->i_size);

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (end == 0)
		return;
	last_blocknr = (end - 1) >> data_bits;

	if (first_blocknr > last_blocknr)
		return;

	freed = nova_delete_file_tree(sb, sih, first_blocknr, 1);

	inode->i_blocks -= (freed * (1 << (data_bits -
				sb->s_blocksize_bits)));

	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(sb, pi, inode->i_size);

	return;
}

/* search the radix tree to find hole or data
 * in the specified range
 * Input:
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
static int nova_lookup_hole_in_range(struct super_block *sb,
	struct nova_inode_info_header *sih,
	unsigned long first_blocknr, unsigned long last_blocknr,
	int *data_found, int *hole_found, int hole)
{
	struct nova_file_write_entry *entry;
	unsigned long blocks = 0;
	int i;

	for (i = first_blocknr; i <= last_blocknr; i++) {
		entry = radix_tree_lookup(&sih->tree, i);
		if (entry) {
			*data_found = 1;
			if (!hole)
				goto done;
		} else {
			*hole_found = 1;
		}

		if (!*hole_found || !hole)
			blocks++;
	}
done:
	return blocks;
}

int nova_assign_nvmm_entry(struct super_block *sb,
	struct nova_inode *pi,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	struct scan_bitmap *bm, bool free)
{
	struct nova_file_write_entry *old_entry;
	void **pentry;
	unsigned long old_nvmm, nvmm;
	unsigned int start_pgoff = entry->pgoff;
	unsigned int num = entry->num_pages;
	unsigned long curr_pgoff;
	int i;
	int ret;
	timing_t assign_time;

	NOVA_START_TIMING(assign_t, assign_time);
	for (i = 0; i < num; i++) {
		curr_pgoff = start_pgoff + i;

		pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
		if (pentry) {
			old_entry = radix_tree_deref_slot(pentry);
			old_nvmm = get_nvmm(sb, old_entry, curr_pgoff);
			if (bm)
				clear_bm(old_nvmm, bm, BM_4K);
			if (free) {
				old_entry->invalid_pages++;
				nova_free_data_blocks(sb, old_nvmm, 1,
							pi->i_blk_type);
			}
			if (bm || free)
				pi->i_blocks--;
			radix_tree_replace_slot(pentry, entry);
		} else {
			ret = radix_tree_insert(&sih->tree, curr_pgoff, entry);
			if (ret) {
				nova_dbg("%s: ERROR %d\n", __func__, ret);
				goto out;
			}
		}

		if (bm) {
			nvmm = get_nvmm(sb, entry, curr_pgoff);
			set_bm(nvmm, bm, BM_4K);
			pi->i_blocks++;
		}
	}

out:
	NOVA_END_TIMING(assign_t, assign_time);

	return ret;
}

static int nova_read_inode(struct super_block *sb, struct inode *inode,
	u64 pi_addr, int rebuild)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode *pi;
	struct nova_inode_info_header *sih;
	int ret = -EIO;
	unsigned long ino;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	inode->i_mode = le16_to_cpu(pi->i_mode);
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
//	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	nova_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino;

	/* check if the inode is active. */
	if (inode->i_mode == 0 || pi->valid == 0) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	inode->i_mapping->a_ops = &nova_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &nova_file_inode_operations;
		inode->i_fop = &nova_dax_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &nova_dir_inode_operations;
		inode->i_fop = &nova_dir_operations;
		if (rebuild && inode->i_ino == NOVA_ROOT_INO) {
			nova_assign_info_header(sb, ino, &sih,
						inode->i_mode, 1);
			nova_dbg_verbose("%s: rebuild root dir\n", __func__);
			nova_rebuild_dir_inode_tree(sb, pi, pi_addr,
					sih, NULL);
			si->header = sih;
		}
		break;
	case S_IFLNK:
		inode->i_op = &nova_symlink_inode_operations;
		break;
	default:
		inode->i_size = 0;
		inode->i_op = &nova_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(pi->dev.rdev));
		break;
	}

	/* Update size and time after rebuild the tree */
	inode->i_size = le64_to_cpu(pi->i_size);
	inode->i_atime.tv_sec = le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

static void nova_get_inode_flags(struct inode *inode, struct nova_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int nova_flags = le32_to_cpu(pi->i_flags);

	nova_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		nova_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		nova_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		nova_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		nova_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		nova_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(nova_flags);
}

static void nova_update_inode(struct inode *inode, struct nova_inode *pi)
{
	nova_memunlock_inode(inode->i_sb, pi);
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_le32(inode->i_generation);
	nova_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);

	nova_memlock_inode(inode->i_sb, pi);
}

static int nova_alloc_unused_inode(struct super_block *sb, unsigned long *ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	i = sbi->first_inode_range;
	NOVA_ASSERT(i);
	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct nova_range_node, node);
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		rb_erase(&next_i->node, &sbi->inode_inuse_tree);
		nova_free_inode_node(sb, next_i);
		sbi->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
	} else {
		nova_dbg("%s: ERROR: new ino %lu, next low %lu\n", __func__,
			new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino = new_ino;
	sbi->s_inodes_used_count++;

	nova_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

static void nova_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *i = NULL;
	struct nova_range_node *curr_node;
	int found = 0;

	nova_dbg_verbose("Free inuse ino: %lu\n", ino);

	found = nova_search_inodetree(sbi, ino, &i);
	if (!found) {
		nova_dbg("%s ERROR: ino %lu not found\n", __func__, ino);
		return;
	}

	if ((ino == i->range_low) && (ino == i->range_high)) {
		/* fits entire node */
		rb_erase(&i->node, &sbi->inode_inuse_tree);
		nova_free_inode_node(sb, i);
		sbi->num_range_node_inode--;
		goto block_found;
	}
	if ((ino == i->range_low) && (ino < i->range_high)) {
		/* Aligns left */
		i->range_low = ino + 1;
		goto block_found;
	}
	if ((ino > i->range_low) && (ino == i->range_high)) {
		/* Aligns right */
		i->range_high = ino - 1;
		goto block_found;
	}
	if ((ino > i->range_low) && (ino < i->range_high)) {
		/* Aligns somewhere in the middle */
		curr_node = nova_alloc_inode_node(sb);
		NOVA_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block */
			goto block_found;
		}
		curr_node->range_low = ino + 1;
		curr_node->range_high = i->range_high;
		i->range_high = ino - 1;
		nova_insert_inodetree(sbi, curr_node);
		sbi->num_range_node_inode++;
		goto block_found;
	}

	nova_error_mng(sb, "Unable to free inode %lu\n", ino);
	nova_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->range_low, i->range_high);

block_found:
	sbi->s_inodes_used_count--;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
static int nova_free_inode(struct inode *inode,
	struct nova_inode_info_header *sih)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	int err = 0;
	timing_t free_time;

	NOVA_START_TIMING(free_inode_t, free_time);

	pi = nova_get_inode(sb, inode);

	if (pi->valid) {
		nova_dbg("%s: inode %lu still valid\n",
				__func__, inode->i_ino);
		pi->valid = 0;
	}

	nova_free_inode_log(sb, pi);
	pi->i_blocks = 0;

	/* Clear the si header, but not free it - leave for future use */
	sih->log_pages = 0;
	sih->i_mode = 0;
	sih->pi_addr = 0;

	mutex_lock(&sbi->inode_table_mutex);
	nova_free_inuse_inode(sb, pi->nova_ino);
	mutex_unlock(&sbi->inode_table_mutex);
	NOVA_END_TIMING(free_inode_t, free_time);
	return err;
}

struct inode *nova_iget(struct super_block *sb, unsigned long ino)
{
	struct nova_inode_info *si;
	struct nova_inode_info_header *sih = NULL;
	struct inode *inode;
	int rebuild = 0;
	u64 pi_addr;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if (ino == NOVA_ROOT_INO) {
		si = NOVA_I(inode);
		sih = nova_find_info_header(sb, ino);
		if (sih)
			si->header = sih;
		else
			rebuild = 1;
		pi_addr = NOVA_ROOT_INO_START;
	} else {
		si = NOVA_I(inode);
		sih = nova_find_info_header(sb, ino);
		if (!sih) {
			nova_dbg("%s: sih for ino %lu not found!\n",
					__func__, ino);
			err = -EACCES;
			goto fail;
		}
		pi_addr = sih->pi_addr;
		si->header = sih;
	}
	if (pi_addr == 0) {
		err = -EACCES;
		goto fail;
	}
	err = nova_read_inode(sb, inode, pi_addr, rebuild);
	if (unlikely(err))
		goto fail;
	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

void nova_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	timing_t evict_time;
	int err = 0;
	int freed = 0;

	if (!sih) {
		nova_dbg("%s: ino %lu sih is NULL!\n", __func__, inode->i_ino);
		BUG();
	}

	NOVA_START_TIMING(evict_inode_t, evict_time);
	nova_dbg_verbose("%s: %lu\n", __func__, inode->i_ino);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			S_ISLNK(inode->i_mode)))
			goto out;
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		/* We need the log to free the blocks from the b-tree */
		switch (inode->i_mode & S_IFMT) {
		case S_IFREG:
			nova_dbgv("%s: file ino %lu\n", __func__, inode->i_ino);
			freed = nova_delete_file_tree(sb, sih, 0, true);
			break;
		case S_IFDIR:
			nova_dbgv("%s: dir ino %lu\n", __func__, inode->i_ino);
			nova_delete_dir_tree(sb, sih);
			break;
		case S_IFLNK:
			/* Log will be freed later */
			break;
		default:
			nova_dbg("%s: unknown\n", __func__);
			break;
		}

		nova_dbg_verbose("%s: Freed %d\n", __func__, freed);
		/* Then we can free the inode */
		err = nova_free_inode(inode, sih);
		if (err)
			goto out;
		pi = NULL; /* we no longer own the nova_inode */

		inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
		inode->i_size = 0;
	}
out:
	/* TODO: Since we don't use page-cache, do we really need the following
	 * call? */
	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
	NOVA_END_TIMING(evict_inode_t, evict_time);
}

/* Returns 0 on failure */
u64 nova_new_nova_inode(struct super_block *sb,
	struct nova_inode_info_header **return_sih)
{
	struct nova_inode_info_header *sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long free_ino = 0;
	u64 ino = 0;
	int ret;
	timing_t new_inode_time;

	NOVA_START_TIMING(new_nova_inode_t, new_inode_time);

	mutex_lock(&sbi->inode_table_mutex);
	ret = nova_alloc_unused_inode(sb, &free_ino);
	if (ret) {
		nova_dbg("%s: alloc inode failed %d\n", __func__, ret);
		mutex_unlock(&sbi->inode_table_mutex);
		return 0;
	}

	nova_assign_info_header(sb, free_ino, &sih, 0, 0);
	mutex_unlock(&sbi->inode_table_mutex);

	ino = free_ino;
	*return_sih = sih;

	NOVA_END_TIMING(new_nova_inode_t, new_inode_time);
	return ino;
}

struct inode *nova_new_vfs_inode(enum nova_new_inode_type type,
	struct inode *dir, u64 pi_addr,
	struct nova_inode_info_header *sih, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr)
{
	struct super_block *sb;
	struct nova_sb_info *sbi;
	struct inode *inode;
	struct nova_inode *diri = NULL;
	struct nova_inode_info *si;
	struct nova_inode *pi;
	int errval;
	timing_t new_inode_time;

	NOVA_START_TIMING(new_vfs_inode_t, new_inode_time);
	sb = dir->i_sb;
	sbi = (struct nova_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode) {
		errval = -ENOMEM;
		goto fail2;
	}

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;

	diri = nova_get_inode(sb, dir);
	if (!diri) {
		errval = -EACCES;
		goto fail2;
	}

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	nova_dbg_verbose("%s: allocating inode %llu @ 0x%llx\n",
					__func__, ino, pi_addr);

	/* chosen inode is in ino */
	inode->i_ino = ino;

	switch (type) {
		case TYPE_CREATE:
			inode->i_op = &nova_file_inode_operations;
			inode->i_mapping->a_ops = &nova_aops_dax;
			inode->i_fop = &nova_dax_file_operations;
			break;
		case TYPE_MKNOD:
			init_special_inode(inode, mode, rdev);
			inode->i_op = &nova_special_inode_operations;
			break;
		case TYPE_SYMLINK:
			inode->i_op = &nova_symlink_inode_operations;
			inode->i_mapping->a_ops = &nova_aops_dax;
			break;
		case TYPE_MKDIR:
			inode->i_op = &nova_dir_inode_operations;
			inode->i_fop = &nova_dir_operations;
			inode->i_mapping->a_ops = &nova_aops_dax;
			set_nlink(inode, 2);
			break;
		default:
			nova_dbg("Unknown new inode type %d\n", type);
			break;
	}

	/*
	 * Pi is part of the dir log so no transaction is needed,
	 * but we need to flush to NVMM.
	 */
	nova_memunlock_inode(sb, pi);
	pi->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	pi->i_flags = nova_mask_flags(mode, diri->i_flags);
	pi->log_head = 0;
	pi->log_tail = 0;
	pi->nova_ino = ino;
	pi->valid = 1;
	nova_memlock_inode(sb, pi);

	si = NOVA_I(inode);
	sih->i_mode = inode->i_mode;
	sih->pi_addr = pi_addr;
	si->header = sih;

	nova_update_inode(inode, pi);

	nova_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));

	if (insert_inode_locked(inode) < 0) {
		nova_err(sb, "nova_new_inode failed ino %lx\n", inode->i_ino);
		errval = -EINVAL;
		goto fail1;
	}

	nova_flush_buffer(&pi, NOVA_INODE_SIZE, 0);
	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
fail2:
	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return ERR_PTR(errval);
}

int nova_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called. */
//	BUG();
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because NOVA always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void nova_dirty_inode(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);

	/* only i_atime should have changed if at all.
	 * we can do in-place atomic update */
	nova_memunlock_inode(sb, pi);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	nova_memlock_inode(sb, pi);
	/* Relax atime persistency */
	nova_flush_buffer(&pi->i_atime, sizeof(pi->i_atime), 0);
}

static void nova_setsize(struct inode *inode, loff_t oldsize, loff_t newsize)
{
	/* We only support truncate regular file */
	if (!(S_ISREG(inode->i_mode))) {
		nova_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
		return;
	}

	nova_dbgv("%s: inode %lu, old size %llu, new size %llu\n",
		__func__, inode->i_ino, oldsize, newsize);

	if (newsize != oldsize)
		i_size_write(inode, newsize);

	/* FIXME: we should make sure that there is nobody reading the inode
	 * before truncating it. Also we need to munmap the truncated range
	 * from application address space, if mmapped. */
	/* synchronize_rcu(); */
	nova_truncate_file_blocks(inode, newsize, oldsize);
}

int nova_getattr(struct vfsmount *mnt, struct dentry *dentry,
		         struct kstat *stat)
{
	struct inode *inode;

	inode = dentry->d_inode;
	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}

static void nova_update_setattr_entry(struct inode *inode,
	struct nova_setattr_logentry *entry, struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid, attr_mask;

	/* These files are in the lowest byte */
	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE |
			ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

	entry->entry_type	= SET_ATTR;
	entry->attr	= ia_valid & attr_mask;
	entry->mode	= cpu_to_le16(inode->i_mode);
	entry->uid	= cpu_to_le32(i_uid_read(inode));
	entry->gid	= cpu_to_le32(i_gid_read(inode));
	entry->atime	= cpu_to_le32(inode->i_atime.tv_sec);
	entry->ctime	= cpu_to_le32(inode->i_ctime.tv_sec);
	entry->mtime	= cpu_to_le32(inode->i_mtime.tv_sec);

	if (ia_valid & ATTR_SIZE)
		entry->size = cpu_to_le64(attr->ia_size);
	else
		entry->size = cpu_to_le64(inode->i_size);

	nova_flush_buffer(entry, sizeof(struct nova_setattr_logentry), 0);
}

void nova_apply_setattr_entry(struct nova_inode *pi,
	struct nova_setattr_logentry *entry)
{
	if (entry->entry_type != SET_ATTR)
		BUG();

	pi->i_mode	= entry->mode;
	pi->i_uid	= entry->uid;
	pi->i_gid	= entry->gid;
	pi->i_size	= entry->size;
	pi->i_atime	= entry->atime;
	pi->i_ctime	= entry->ctime;
	pi->i_mtime	= entry->mtime;

	/* Do not flush now */
}

/* Returns new tail after append */
u64 nova_append_setattr_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct iattr *attr, u64 tail)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	struct nova_setattr_logentry *entry;
	u64 curr_p, new_tail = 0;
	size_t size = sizeof(struct nova_setattr_logentry);
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);
	nova_dbg_verbose("%s: inode %lu attr change\n",
				__func__, inode->i_ino);

	curr_p = nova_get_append_head(sb, pi, sih, tail, size, 0, 1);
	if (curr_p == 0)
		BUG();

	entry = (struct nova_setattr_logentry *)nova_get_block(sb, curr_p);
	/* inode is already updated with attr */
	nova_update_setattr_entry(inode, entry, attr);
	new_tail = curr_p + size;

	NOVA_END_TIMING(append_entry_t, append_time);
	return new_tail;
}

int nova_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	int ret;
	unsigned int ia_valid = attr->ia_valid, attr_mask;
	loff_t oldsize = inode->i_size;
	u64 new_tail;
	timing_t setattr_time;

	NOVA_START_TIMING(setattr_t, setattr_time);
	if (!pi)
		return -EACCES;

	ret = inode_change_ok(inode, attr);
	if (ret)
		return ret;

	/* Update inode with attr except for size */
	setattr_copy(inode, attr);

	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME
			| ATTR_MTIME | ATTR_CTIME;

	ia_valid = ia_valid & attr_mask;

	if (ia_valid == 0)
		return ret;

	/* We are holding i_mutex so OK to append the log */
	new_tail = nova_append_setattr_entry(sb, pi, inode, attr, 0);

	nova_update_tail(pi, new_tail);

	/* Only after log entry is committed, we can truncate size */
	if ((ia_valid & ATTR_SIZE) && (attr->ia_size != oldsize ||
			pi->i_flags & cpu_to_le32(NOVA_EOFBLOCKS_FL))) {
//		nova_set_blocksize_hint(sb, inode, pi, attr->ia_size);

		/* now we can freely truncate the inode */
		nova_setsize(inode, oldsize, attr->ia_size);
	}

	NOVA_END_TIMING(setattr_t, setattr_time);
	return ret;
}

void nova_set_inode_flags(struct inode *inode, struct nova_inode *pi,
	unsigned int flags)
{
	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,9)

static ssize_t nova_direct_IO(int rw, struct kiocb *iocb,
	struct iov_iter *iter, loff_t offset)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_mapping->host;
	loff_t end = offset;
	ssize_t err = -EINVAL;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;
	timing_t dio_time;

	NOVA_START_TIMING(direct_IO_t, dio_time);
	for (seg = 0; seg < nr_segs; seg++) {
		end += iv->iov_len;
		iv++;
	}

	if ((rw == WRITE) && end > i_size_read(inode)) {
		/* FIXME: Do we need to check for out of bounds IO for R/W */
		printk(KERN_ERR "nova: needs to grow (size = %lld)\n", end);
		return err;
	}

	nova_dbg_verbose("%s\n", __func__);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (rw == READ) {
			err = nova_dax_file_read(filp, iv->iov_base,
					iv->iov_len, &offset);
		} else if (rw == WRITE) {
			err = nova_cow_file_write(filp, iv->iov_base,
					iv->iov_len, &offset, false);
		}
		if (err <= 0)
			goto err;
		if (iter->count > iv->iov_len)
			iter->count -= iv->iov_len;
		else
			iter->count = 0;
		iter->nr_segs--;
		iv++;
	}
	if (offset != end)
		printk(KERN_ERR "nova: direct_IO: end = %lld"
			"but offset = %lld\n", end, offset);
err:
	NOVA_END_TIMING(direct_IO_t, dio_time);
	return err;
}

#else

static ssize_t nova_direct_IO(struct kiocb *iocb,
	struct iov_iter *iter, loff_t offset)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = filp->f_mapping->host;
	loff_t end = offset;
	size_t count = iov_iter_count(iter);
	ssize_t err = -EINVAL;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;
	timing_t dio_time;

	NOVA_START_TIMING(direct_IO_t, dio_time);
	end = offset + count;

	if ((iov_iter_rw(iter) == WRITE) && end > i_size_read(inode)) {
		/* FIXME: Do we need to check for out of bounds IO for R/W */
		printk(KERN_ERR "nova: needs to grow (size = %lld)\n", end);
		return err;
	}

	nova_dbg_verbose("%s\n", __func__);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			err = nova_dax_file_read(filp, iv->iov_base,
					iv->iov_len, &offset);
		} else if (iov_iter_rw(iter) == WRITE) {
			err = nova_cow_file_write(filp, iv->iov_base,
					iv->iov_len, &offset, false);
		}
		if (err <= 0)
			goto err;
		if (iter->count > iv->iov_len)
			iter->count -= iv->iov_len;
		else
			iter->count = 0;
		iter->nr_segs--;
		iv++;
	}
	if (offset != end)
		printk(KERN_ERR "nova: direct_IO: end = %lld"
			"but offset = %lld\n", end, offset);
err:
	NOVA_END_TIMING(direct_IO_t, dio_time);
	return err;
}

#endif

static int nova_coalesce_log_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long first_blocknr,
	unsigned long num_pages)
{
	unsigned long next_blocknr;
	u64 curr_block;
	struct nova_inode_log_page *curr_page;
	int i;

	if (prev_blocknr) {
		/* Link prev block and newly allocated head block */
		curr_block = nova_get_block_off(sb, prev_blocknr,
						NOVA_BLOCK_TYPE_4K);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		curr_page->page_tail.next_page = nova_get_block_off(sb,
				first_blocknr, NOVA_BLOCK_TYPE_4K);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);
	curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		curr_page->page_tail.next_page = nova_get_block_off(sb,
				next_blocknr, NOVA_BLOCK_TYPE_4K);
		curr_page++;
		next_blocknr++;
	}

	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode *pi, unsigned long num_pages,
	u64 *new_block)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = nova_new_log_blocks(sb, pi->nova_ino, &new_inode_blocknr,
					num_pages, NOVA_BLOCK_TYPE_4K, 1);

	if (allocated <= 0) {
		nova_err(sb, "ERROR: no inode log page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	ret_pages += allocated;
	num_pages -= allocated;
	nova_dbg_verbose("Pi %llu: Alloc %d log blocks @ 0x%lx\n",
			pi->nova_ino, allocated, new_inode_blocknr);

	/* Coalesce the pages */
	nova_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated);
	first_blocknr = new_inode_blocknr;
	prev_blocknr = new_inode_blocknr + allocated - 1;

	/* Allocate remaining pages */
	while (num_pages) {
		allocated = nova_new_log_blocks(sb, pi->nova_ino,
					&new_inode_blocknr, num_pages,
					NOVA_BLOCK_TYPE_4K, 1);

		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			nova_err(sb, "ERROR: no inode log page available: "
				"%d %d\n", num_pages, allocated);
			return allocated;
		}
		ret_pages += allocated;
		num_pages -= allocated;
		nova_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr,
						allocated);
		prev_blocknr = new_inode_blocknr + allocated - 1;
	}

	*new_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);

	return ret_pages;
}

/*
 * Copy alive log entries to the new log,
 * merge entries if possible
 */
#if 0
int nova_inode_log_gabbage_collection(struct super_block *sb,
	struct nova_inode *pi, u64 new_block, unsigned long num_pages)
{
	struct nova_file_write_entry *curr_entry, *new_entry;
	u64 old_head, new_head;
	struct nova_inode_log_page *last_page;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	old_head = pi->log_head;
	new_head = new_block;
	last_page = (struct nova_inode_log_page *)
		nova_get_block(sb, new_block + ((num_pages - 1) << PAGE_SHIFT));

	while (old_head != pi->log_tail) {
		if (is_last_entry(old_head))
			old_head = next_log_page(sb, old_head);
		if (is_last_entry(new_head))
			new_head = next_log_page(sb, new_head);

		if (old_head == pi->log_tail)
			break;

		curr_entry = nova_get_block(sb, old_head);
		if (curr_entry->num_pages == curr_entry->invalid_pages) {
			goto update;
		}
		new_entry = nova_get_block(sb, new_head);
		memcpy(new_entry, curr_entry, entry_size);
update:
		old_head += entry_size;
		new_head += entry_size;
	}

	last_page->page_tail.next_page = pi->log_head;
	nova_flush_buffer(nova_get_block(sb, new_block),
				num_pages * PAGE_SIZE, 1);
	return 0;
}
#endif

static bool curr_page_invalid(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_log_page *curr_page)
{
	struct nova_file_write_entry *entry;
	int i;
	timing_t check_time;

	NOVA_START_TIMING(check_invalid_t, check_time);
	for (i = 0; i < ENTRIES_PER_PAGE; i++) {
		entry = &curr_page->entries[i];
		/* Do not recycle inode change entry */
		if (nova_get_entry_type(entry) != FILE_WRITE) {
			NOVA_END_TIMING(check_invalid_t, check_time);
			return false;
		}
		if (entry->num_pages != entry->invalid_pages) {
			NOVA_END_TIMING(check_invalid_t, check_time);
			return false;
		}
	}

	NOVA_END_TIMING(check_invalid_t, check_time);
	return true;
}

static void free_curr_page(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_log_page *curr_page,
	struct nova_inode_log_page *last_page, u64 curr_head)
{
	unsigned short btype = pi->i_blk_type;

	last_page->page_tail.next_page = curr_page->page_tail.next_page;
	nova_flush_buffer(&last_page->page_tail.next_page, CACHELINE_SIZE, 1);
	nova_free_log_blocks(sb, nova_get_blocknr(sb, curr_head, btype),
					1, btype);
}

int nova_inode_log_garbage_collection(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_tail, u64 new_block, int num_pages)
{
	u64 curr, next, possible_head = 0;
	u64 page_tail;
	int found_head = 0;
	struct nova_inode_log_page *last_page = NULL;
	struct nova_inode_log_page *curr_page = NULL;
	int first_need_free = 0;
	unsigned short btype = pi->i_blk_type;
	int freed_pages = 0;
	timing_t gc_time;

	NOVA_START_TIMING(log_gc_t, gc_time);
	curr = pi->log_head;

	nova_dbg_verbose("%s: log head 0x%llx, tail 0x%llx\n",
				__func__, curr, curr_tail);
	while (1) {
		if (curr >> PAGE_SHIFT == pi->log_tail >> PAGE_SHIFT) {
			/* Don't recycle tail page */
			if (found_head == 0)
				possible_head = cpu_to_le64(curr);
			break;
		}

		curr_page = (struct nova_inode_log_page *)
					nova_get_block(sb, curr);
		next = curr_page->page_tail.next_page;
		nova_dbg_verbose("curr 0x%llx, next 0x%llx\n", curr, next);
		if (curr_page_invalid(sb, pi, curr_page)) {
			nova_dbg_verbose("curr page %p invalid\n", curr_page);
			if (curr == pi->log_head) {
				/* Free first page later */
				first_need_free = 1;
				last_page = curr_page;
			} else {
				nova_dbg_verbose("Free log block 0x%llx\n",
						curr >> PAGE_SHIFT);
				free_curr_page(sb, pi, curr_page, last_page,
						curr);
			}
			gc_pages++;
			freed_pages++;
		} else {
			if (found_head == 0) {
				possible_head = cpu_to_le64(curr);
				found_head = 1;
			}
			last_page = curr_page;
		}

		curr = next;
		checked_pages++;
		if (curr == 0)
			break;
	}

	page_tail = PAGE_TAIL(curr_tail);
	((struct nova_inode_page_tail *)
		nova_get_block(sb, page_tail))->next_page = new_block;

	curr = pi->log_head;

	pi->log_head = possible_head;
	nova_dbg_verbose("%s: %d new head 0x%llx\n", __func__,
					found_head, possible_head);
	nova_dbg_verbose("Num pages %d, freed %d\n", num_pages, freed_pages);
	sih->log_pages += num_pages - freed_pages;
	pi->i_blocks += num_pages - freed_pages;
	/* Don't update log tail pointer here */
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	if (first_need_free) {
		nova_dbg_verbose("Free log head block 0x%llx\n",
					curr >> PAGE_SHIFT);
		nova_free_log_blocks(sb, nova_get_blocknr(sb, curr, btype),
					1, btype);
	}
	NOVA_END_TIMING(log_gc_t, gc_time);
	return 0;
}

u64 nova_extend_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 curr_p, int is_file)
{
	u64 new_block;
	int allocated;
	unsigned long num_pages;
	u64 page_tail;

	if (curr_p == 0) {
		allocated = nova_allocate_inode_log_pages(sb, pi,
					1, &new_block);
		if (allocated != 1) {
			nova_err(sb, "ERROR: no inode log page "
					"available\n");
			return 0;
		}
		pi->log_tail = new_block;
		nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
		pi->log_head = new_block;
		sih->log_pages = 1;
		pi->i_blocks++;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
	} else {
		num_pages = sih->log_pages >= 256 ?
				256 : sih->log_pages;
//		nova_dbg("Before append log pages:\n");
//		nova_print_inode_log_page(sb, inode);
		allocated = nova_allocate_inode_log_pages(sb, pi,
					num_pages, &new_block);
		nova_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
		if (allocated <= 0) {
			nova_err(sb, "ERROR: no inode log page "
					"available\n");
			return 0;
		}

		if (is_file) {
			nova_inode_log_garbage_collection(sb, pi, sih, curr_p,
						new_block, allocated);
		} else {
			/* TODO: Disable GC for dir inode by now */
			page_tail = PAGE_TAIL(curr_p);
			((struct nova_inode_page_tail *)
				nova_get_block(sb, page_tail))->next_page
								= new_block;
			sih->log_pages += num_pages;
			pi->i_blocks += num_pages;
		}

//		nova_dbg("After append log pages:\n");
//		nova_print_inode_log_page(sb, inode);
		/* Atomic switch to new log */
//		nova_switch_to_new_log(sb, pi, new_block, num_pages);
	}
	return new_block;
}

u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size,
	int new_inode, int is_file)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else
		curr_p = pi->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, new_inode) &&
				next_log_page(sb, curr_p) == 0)) {
		curr_p = nova_extend_inode_log(sb, pi, sih, curr_p, is_file);
		if (curr_p == 0)
			return 0;
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	return  curr_p;
}

/*
 * Append a nova_file_write_entry to the current nova_inode_log_page.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 */
u64 nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_entry *data, u64 tail)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	struct nova_file_write_entry *entry;
	u64 curr_p;
	size_t size = sizeof(struct nova_file_write_entry);
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);

	curr_p = nova_get_append_head(sb, pi, sih, tail, size, 0, 1);
	if (curr_p == 0)
		return curr_p;

	entry = (struct nova_file_write_entry *)nova_get_block(sb, curr_p);
	memcpy_to_pmem_nocache(entry, data,
			sizeof(struct nova_file_write_entry));
	nova_dbg_verbose("file %lu entry @ 0x%llx: pgoff %u, num %u, "
			"block %llu, size %llu\n", inode->i_ino,
			curr_p, entry->pgoff, entry->num_pages,
			entry->block >> PAGE_SHIFT, entry->size);
	/* entry->invalid is set to 0 */

	NOVA_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

void nova_free_inode_log(struct super_block *sb, struct nova_inode *pi)
{
	struct nova_inode_log_page *curr_page;
	u64 curr_block;
	unsigned long blocknr, start_blocknr = 0;
	int num_free = 0;
	u32 btype = pi->i_blk_type;
	timing_t free_time;

	if (pi->log_head == 0 || pi->log_tail == 0)
		return;

	NOVA_START_TIMING(free_inode_log_t, free_time);

	curr_block = pi->log_head;
	while (curr_block) {
		if (curr_block & INVALID_MASK) {
			nova_dbg("%s: ERROR: invalid block %llu\n",
					__func__, curr_block);
			break;
		}
		curr_page = (struct nova_inode_log_page *)nova_get_block(sb,
							curr_block);
		blocknr = nova_get_blocknr(sb, le64_to_cpu(curr_block),
				    btype);
		nova_dbg_verbose("%s: free page %llu\n", __func__, curr_block);
		curr_block = curr_page->page_tail.next_page;

		if (start_blocknr == 0) {
			start_blocknr = blocknr;
			num_free = 1;
		} else {
			if (blocknr == start_blocknr + num_free) {
				num_free++;
			} else {
				/* A new start */
				nova_free_log_blocks(sb, start_blocknr,
					num_free, btype);
				start_blocknr = blocknr;
				num_free = 1;
			}
		}
	}
	if (start_blocknr)
		nova_free_log_blocks(sb, start_blocknr,	num_free, btype);

	pi->log_head = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	nova_update_tail(pi, 0);
	NOVA_END_TIMING(free_inode_log_t, free_time);
}

int nova_free_dram_resource(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	int freed = 0;

	if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode)))
		return 0;

	if (S_ISREG(sih->i_mode)) {
		freed = nova_delete_file_tree(sb, sih, 0, false);
	} else {
		nova_delete_dir_tree(sb, sih);
		freed = 1;
	}

	return freed;
}

static inline void nova_rebuild_file_time_and_size(struct super_block *sb,
	struct nova_inode *pi, struct nova_file_write_entry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = cpu_to_le32(entry->mtime);
	pi->i_mtime = cpu_to_le32(entry->mtime);
	pi->i_size = cpu_to_le64(entry->size);
}

int nova_rebuild_file_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih, struct scan_bitmap *bm)
{
	struct nova_file_write_entry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *link_change_entry = NULL;
	struct nova_inode_log_page *curr_page;
	u64 ino = pi->nova_ino;
	void *addr;
	u64 curr_p;
	u64 next;
	u8 type;

	nova_dbg_verbose("Rebuild file inode %llu tree\n", ino);
	/*
	 * We will regenerate the tree during blocks assignment.
	 * Set height to 0.
	 */
	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, pi->log_tail);
	if (curr_p == 0 && pi->log_tail == 0)
		return 0;

	sih->log_pages = 1;
	if (bm) {
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
	}
	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p,
				sizeof(struct nova_file_write_entry), 0)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
			if (bm) {
				BUG_ON(curr_p & (PAGE_SIZE - 1));
				set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
			}
		}

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				attr_entry =
					(struct nova_setattr_logentry *)addr;
				nova_apply_setattr_entry(pi, attr_entry);
				curr_p += sizeof(struct nova_setattr_logentry);
				continue;
			case LINK_CHANGE:
				link_change_entry =
					(struct nova_link_change_entry *)addr;
				nova_apply_link_change_entry(pi,
							link_change_entry);
				curr_p += sizeof(struct nova_link_change_entry);
				continue;
			case FILE_WRITE:
				break;
			default:
				nova_dbg("%s: unknown type %d, 0x%llx\n",
							__func__, type, curr_p);
				NOVA_ASSERT(0);
		}

		entry = (struct nova_file_write_entry *)addr;
//		nova_print_inode_entry(entry);

		if (entry->num_pages != entry->invalid_pages) {
			/*
			 * The overlaped blocks are already freed.
			 * Don't double free them, just re-assign the pointers.
			 */
			nova_assign_nvmm_entry(sb, pi, sih, entry,
						bm, false);
		}

		nova_rebuild_file_time_and_size(sb, pi, entry);
		curr_p += sizeof(struct nova_file_write_entry);
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le16_to_cpu(pi->i_mode);
	nova_flush_buffer(pi, sizeof(struct nova_inode), 0);

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr_p);
	while ((next = curr_page->page_tail.next_page) != 0) {
		sih->log_pages++;
		curr_p = next;
		if (bm) {
			BUG_ON(curr_p & (PAGE_SIZE - 1));
			set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
		}
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr_p);
	}

	if (bm)
		pi->i_blocks += sih->log_pages;

//	nova_print_inode_log_page(sb, inode);
	return 0;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long nova_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	unsigned long blocks = 0, offset_in_block;
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !sih->i_size) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & ((1UL << data_bits) - 1);

	first_blocknr = *offset >> data_bits;
	last_blocknr = inode->i_size >> data_bits;

	nova_dbg_verbose("find_region offset %llx, first_blocknr %lx,"
		" last_blocknr %lx hole %d\n",
		  *offset, first_blocknr, last_blocknr, hole);

	blocks = nova_lookup_hole_in_range(inode->i_sb, sih,
		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

	/* Searching data but only hole found till the end */
	if (!hole && !data_found && hole_found)
		return -ENXIO;

	if (data_found && !hole_found) {
		/* Searching data but we are already into them */
		if (hole)
			/* Searching hole but only data found, go to the end */
			*offset = inode->i_size;
		return 0;
	}

	/* Searching for hole, hole found and starting inside an hole */
	if (hole && hole_found && !blocks) {
		/* we found data after it */
		if (!data_found)
			/* last hole */
			*offset = inode->i_size;
		return 0;
	}

	if (offset_in_block) {
		blocks--;
		*offset += (blocks << data_bits) +
			   ((1 << data_bits) - offset_in_block);
	} else {
		*offset += blocks << data_bits;
	}

	return 0;
}

const struct address_space_operations nova_aops_dax = {
	.direct_IO		= nova_direct_IO,
	/*.dax_mem_protect	= nova_dax_mem_protect,*/
};
