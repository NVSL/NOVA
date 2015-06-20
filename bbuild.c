/*
 * PMFS emulated persistence. This file contains code to 
 * handle data blocks of various sizes efficiently.
 *
 * Persistent Memory File System
 * Copyright (c) 2012-2013, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include "pmfs.h"

static void pmfs_free_header(struct super_block *sb,
	struct pmfs_inode_info_header *sih);

static void pmfs_clear_datablock_inode(struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	pmfs_transaction_t *trans;

	/* 2 log entry for inode */
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES);
	if (IS_ERR(trans))
		return;
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	pmfs_memunlock_inode(sb, pi);
	memset(pi, 0, MAX_DATA_PER_LENTRY);
	pmfs_memlock_inode(sb, pi);

	/* commit the transaction */
	pmfs_commit_transaction(sb, trans);
}

static void pmfs_init_blockmap_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_blocknode_lowhigh *entry;
	struct pmfs_blocknode *blknode;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	unsigned long i;
	unsigned long num_blocknode;
	u64 curr_p;

	num_blocknode = sbi->num_blocknode_block;
	sbi->num_blocknode_block = 0;
	curr_p = pi->log_head;
	if (curr_p == 0)
		pmfs_dbg("%s: pi head is 0!\n", __func__);

	for (i = 0; i < num_blocknode; i++) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			pmfs_dbg("%s: curr_p is NULL!\n", __func__);
			BUG();
		}

		entry = (struct pmfs_blocknode_lowhigh *)pmfs_get_block(sb,
							curr_p);
		blknode = pmfs_alloc_block_node(sb);
		if (blknode == NULL)
			PMFS_ASSERT(0);
		blknode->block_low = entry->block_low;
		blknode->block_high = entry->block_high;
		list_add_tail(&blknode->link, &sbi->block_inuse_head);
		pmfs_insert_blocknode_blocktree(sbi, blknode);

		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

	if (curr_p != pi->log_tail)
		pmfs_dbg("%s: curr_p 0x%llx, tail 0x%llx, %lu blocknodes\n",
			__func__, curr_p, pi->log_tail, num_blocknode);
	pmfs_free_inode_log(sb, pi);
}

static void pmfs_init_inode_list_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_INODELIST_INO);
	struct pmfs_blocknode_lowhigh *entry;
	struct pmfs_blocknode *blknode;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	unsigned long num_blocknode;
	unsigned long i;
	u64 curr_p;

	num_blocknode = sbi->num_blocknode_inode;
	sbi->num_blocknode_inode = 0;
	curr_p = pi->log_head;
	if (curr_p == 0)
		pmfs_dbg("%s: pi head is 0!\n", __func__);

	for (i = 0; i < num_blocknode; i++) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			pmfs_dbg("%s: curr_p is NULL!\n", __func__);
			BUG();
		}

		entry = (struct pmfs_blocknode_lowhigh *)pmfs_get_block(sb,
							curr_p);
		blknode = pmfs_alloc_inode_node(sb);
		if (blknode == NULL)
			PMFS_ASSERT(0);
		blknode->block_low = entry->block_low;
		blknode->block_high = entry->block_high;
		list_add_tail(&blknode->link, &sbi->inode_inuse_head);
		pmfs_insert_blocknode_inodetree(sbi, blknode);

		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

	if (curr_p != pi->log_tail)
		pmfs_dbg("%s: curr_p 0x%llx, tail 0x%llx, %lu blocknodes\n",
			__func__, curr_p, pi->log_tail, num_blocknode);
	pmfs_free_inode_log(sb, pi);
}

static bool pmfs_can_skip_full_scan(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	sbi->num_blocknode_block =
		le64_to_cpu(super->s_num_blocknode_block);
	sbi->num_blocknode_inode =
		le64_to_cpu(super->s_num_blocknode_inode);
	sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
	sbi->s_inodes_count = le32_to_cpu(super->s_inodes_count);
	sbi->s_free_inodes_count = le32_to_cpu(super->s_free_inodes_count);
	sbi->s_inodes_used_count = le32_to_cpu(super->s_inodes_used_count);
	sbi->s_free_inode_hint = le32_to_cpu(super->s_free_inode_hint);
	sbi->s_max_inode = le32_to_cpu(super->s_max_inode);

	pmfs_init_blockmap_from_inode(sb);
	pmfs_init_inode_list_from_inode(sb);

	return true;
}

#if 0
static int pmfs_allocate_datablock_block_inode(pmfs_transaction_t *trans,
	struct super_block *sb, struct pmfs_inode *pi, unsigned long num_blocks)
{
	int errval;
	
	pmfs_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_blk_type = PMFS_BLOCK_TYPE_4K;
	pi->i_flags = 0;
	pi->height = 0;
	pi->i_dtime = 0; 
	pi->i_size = cpu_to_le64(num_blocks << sb->s_blocksize_bits);
	pmfs_memlock_inode(sb, pi);

	errval = __pmfs_alloc_blocks(trans, sb, pi, 0, num_blocks, false);

	return errval;
}

void pmfs_save_blocknode_mappings(struct super_block *sb)
{
	unsigned long num_blocks, blocknr;
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_blocknode_lowhigh *p;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i;
	struct pmfs_super_block *super;
	pmfs_transaction_t *trans;
	u64 bp;
	int step = 0;
	int j, k;
	int errval;
	
	num_blocks = ((sbi->num_blocknode_block * sizeof(struct
		pmfs_blocknode_lowhigh) - 1) >> sb->s_blocksize_bits) + 1;

	/* 2 log entry for inode, 2 lentry for super-block */
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES + MAX_SB_LENTRIES);
	if (IS_ERR(trans))
		return;

	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	errval = pmfs_allocate_datablock_block_inode(trans, sb, pi, num_blocks);

	if (errval != 0) {
		pmfs_dbg("Error saving the blocknode mappings: %d\n", errval);
		pmfs_abort_transaction(sb, trans);
		return;
	}


	j = 0;
	k = 0;
	p = NULL;
	list_for_each_entry(i, head, link) {
		blocknr = k >> 8;
		if (j == 0) {
			/* Find, get and unlock new data block */
			bp = __pmfs_find_inode(sb, pi, blocknr);
			p = pmfs_get_block(sb, bp); 
			pmfs_memunlock_block(sb, p);
		}
		p[j].block_low = cpu_to_le64(i->block_low);
		p[j].block_high = cpu_to_le64(i->block_high);
		j++;

		pmfs_dbg_verbose("%s: save blocknode %d, %lu %lu\n",
				__func__, step,	i->block_low, i->block_high);
		if (j == 256) {
			j = 0;
			/* Lock the data block */
			pmfs_memlock_block(sb, p);
			pmfs_flush_buffer(p, 4096, false);
		}
		
		k++;
		step++;
	}

	pmfs_dbg("%s: %lu blocknodes, step %d\n",
		__func__, sbi->num_blocknode_block, step);

	/* Lock the block */	
	if (j) {
		pmfs_flush_buffer(p, j << 4, false);
		pmfs_memlock_block(sb, p);	
	}	

	/* 
	 * save the total allocated blocknode mappings 
	 * in super block
	 */
	super = pmfs_get_super(sb);
	pmfs_add_logentry(sb, trans, &super->s_wtime,
			PMFS_FAST_MOUNT_FIELD_SIZE, LE_DATA);

	pmfs_memunlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);

	super->s_wtime = cpu_to_le32(get_seconds());
	super->s_num_blocknode_block =
			cpu_to_le64(sbi->num_blocknode_block);
	super->s_num_blocknode_inode =
			cpu_to_le64(sbi->num_blocknode_inode);
	super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
	super->s_inodes_count = cpu_to_le32(sbi->s_inodes_count);
	super->s_free_inodes_count = cpu_to_le32(sbi->s_free_inodes_count);
	super->s_inodes_used_count = cpu_to_le32(sbi->s_inodes_used_count);
	super->s_free_inode_hint = cpu_to_le32(sbi->s_free_inode_hint);
	super->s_max_inode = cpu_to_le32(sbi->s_max_inode);

	pmfs_memlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);
	/* commit the transaction */
	pmfs_commit_transaction(sb, trans);
}
#endif

static u64 pmfs_append_blocknode_entry(struct super_block *sb,
	struct pmfs_blocknode *i, u64 tail)
{
	u64 curr_p;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	struct pmfs_blocknode_lowhigh *entry;
	timing_t append_time;

	PMFS_START_TIMING(append_entry_t, append_time);

	curr_p = tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, 0) &&
				next_log_page(sb, curr_p) == 0)) {
		pmfs_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct pmfs_blocknode_lowhigh *)pmfs_get_block(sb, curr_p);
	entry->block_low = i->block_low;
	entry->block_high = i->block_high;
	pmfs_dbg_verbose("append entry block low %lu, high %lu\n",
			i->block_low, i->block_high);

	pmfs_flush_buffer(entry, sizeof(struct pmfs_blocknode_lowhigh), 0);
out:
	PMFS_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

static u64 pmfs_append_alive_inode_entry(struct super_block *sb,
	struct pmfs_inode *inode_table, struct pmfs_inode *pi,
	struct pmfs_inode_info_header *sih,
	struct pmfs_inode_info_header *inode_table_sih)
{
	size_t size = sizeof(struct pmfs_alive_inode_entry);
	struct pmfs_alive_inode_entry *entry;
	u64 curr_p;
	timing_t append_time;

	PMFS_START_TIMING(append_entry_t, append_time);

	curr_p = inode_table->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, 0) &&
				next_log_page(sb, curr_p) == 0)) {
		curr_p = pmfs_extend_inode_log(sb, inode_table,
						inode_table_sih, curr_p, 0);
		if (curr_p == 0)
			goto out;
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct pmfs_alive_inode_entry *)pmfs_get_block(sb, curr_p);
	if (sih->ino != pi->pmfs_ino << PMFS_INODE_BITS)
		pmfs_dbg("%s: inode number not match! sih %llu, pi %llu\n",
			__func__, sih->ino, pi->pmfs_ino << PMFS_INODE_BITS);
	entry->pi_addr = sih->pi_addr;
	pmfs_dbg_verbose("append entry alive inode %llu, pmfs inode 0x%llx\n",
			sih->ino, sih->pi_addr);

	pmfs_flush_buffer(entry, sizeof(struct pmfs_alive_inode_entry), 0);
	/* flush at the end */
	inode_table->log_tail = curr_p + size;
out:
	PMFS_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

void pmfs_save_inode_list_to_log(struct super_block *sb)
{
	unsigned long num_blocks;
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_INODELIST_INO);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->inode_inuse_head);
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	struct pmfs_blocknode *i;
	int step = 0;
	u64 curr_entry = 0;
	u64 temp_tail;
	u64 new_block;
	int allocated;

	num_blocks = sbi->num_blocknode_inode / BLOCKNODE_PER_PAGE;
	if (sbi->num_blocknode_inode % BLOCKNODE_PER_PAGE)
		num_blocks++;

	allocated = pmfs_allocate_inode_log_pages(sb, pi, num_blocks,
						&new_block);
	if (allocated != num_blocks) {
		pmfs_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	pi->log_head = new_block;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	temp_tail = new_block;
	list_for_each_entry(i, head, link) {
		step++;
		curr_entry = pmfs_append_blocknode_entry(sb, i, temp_tail);
		temp_tail = curr_entry + size;
	}

	pmfs_update_tail(pi, temp_tail);

	pmfs_dbg("%s: %lu inode nodes, step %d, pi head 0x%llx, tail 0x%llx\n",
		__func__, sbi->num_blocknode_inode, step, pi->log_head,
		pi->log_tail);
}

void pmfs_save_blocknode_mappings_to_log(struct super_block *sb)
{
	unsigned long num_blocks;
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	struct pmfs_blocknode *i;
	struct pmfs_super_block *super;
	int step = 0;
	int allocated;
	u64 new_block = 0;
	pmfs_transaction_t *trans;
	u64 curr_entry = 0;
	u64 temp_tail;

	/* Allocate log pages before save blocknode mappings */
	num_blocks = sbi->num_blocknode_block / BLOCKNODE_PER_PAGE;
	if (sbi->num_blocknode_block % BLOCKNODE_PER_PAGE)
		num_blocks++;

	/* 2 entries for super-block */
	trans = pmfs_new_transaction(sb, MAX_SB_LENTRIES);
	if (IS_ERR(trans))
		return;

	allocated = pmfs_allocate_inode_log_pages(sb, pi, num_blocks,
						&new_block);
	if (allocated != num_blocks) {
		pmfs_dbg("Error saving blocknode mappings: %d\n", allocated);
		pmfs_abort_transaction(sb, trans);
		return;
	}

	pmfs_dbg("%s: %lu blocknodes, step %d, pi head 0x%llx, tail 0x%llx\n",
		__func__, sbi->num_blocknode_block, step, pi->log_head,
		pi->log_tail);

	/*
	 * save the total allocated blocknode mappings
	 * in super block
	 */
	super = pmfs_get_super(sb);
	pmfs_add_logentry(sb, trans, &super->s_wtime,
			PMFS_FAST_MOUNT_FIELD_SIZE, LE_DATA);

	pmfs_memunlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);

	super->s_wtime = cpu_to_le32(get_seconds());
	super->s_num_blocknode_block =
			cpu_to_le64(sbi->num_blocknode_block);
	super->s_num_blocknode_inode =
			cpu_to_le64(sbi->num_blocknode_inode);
	super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
	super->s_inodes_count = cpu_to_le32(sbi->s_inodes_count);
	super->s_free_inodes_count = cpu_to_le32(sbi->s_free_inodes_count);
	super->s_inodes_used_count = cpu_to_le32(sbi->s_inodes_used_count);
	super->s_free_inode_hint = cpu_to_le32(sbi->s_free_inode_hint);
	super->s_max_inode = cpu_to_le32(sbi->s_max_inode);

	pmfs_memlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);
	/* commit the transaction */
	pmfs_commit_transaction(sb, trans);
	pmfs_flush_buffer(super, PMFS_SB_SIZE, 1);

	/* Finally update log head and tail */
	pi->log_head = new_block;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	temp_tail = new_block;
	list_for_each_entry(i, head, link) {
		step++;
		curr_entry = pmfs_append_blocknode_entry(sb, i, temp_tail);
		temp_tail = curr_entry + size;
	}

	pmfs_update_tail(pi, temp_tail);
}

static void pmfs_inode_crawl_recursive(struct super_block *sb,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u8 btype)
{
	__le64 *node;
	unsigned int i;

	if (height == 0) {
		/* This is the data block */
		if (btype == PMFS_BLOCK_TYPE_4K) {
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
		} else if (btype == PMFS_BLOCK_TYPE_2M) {
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		} else {
			set_bit(block >> PAGE_SHIFT_1G, bm->bitmap_1G);
		}
		return;
	}

	node = pmfs_get_block(sb, block);
	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		pmfs_inode_crawl_recursive(sb, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}

static inline void pmfs_inode_crawl(struct super_block *sb,
				struct scan_bitmap *bm, struct pmfs_inode *pi)
{
	if (pi->root == 0)
		return;
	pmfs_inode_crawl_recursive(sb, bm, le64_to_cpu(pi->root), pi->height,
					pi->i_blk_type);
}

static void pmfs_inode_table_crawl_recursive(struct super_block *sb,
				struct scan_bitmap *bm, unsigned long block,
				u32 height, u32 btype)
{
	__le64 *node;
	unsigned int i;
	struct pmfs_inode *pi;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	node = pmfs_get_block(sb, block);

	if (height == 0) {
		unsigned int inodes_per_block = INODES_PER_BLOCK(btype);
		if (likely(btype == PMFS_BLOCK_TYPE_2M))
			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
		else
			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

		sbi->s_inodes_count += inodes_per_block;
		for (i = 0; i < inodes_per_block; i++) {
			pi = (struct pmfs_inode *)((void *)node +
                                                        PMFS_INODE_SIZE * i);
			if (le16_to_cpu(pi->i_links_count) == 0 &&
				(le16_to_cpu(pi->i_mode) == 0 ||
				le32_to_cpu(pi->i_dtime))) {
					/* Empty inode */
					continue;
			}
			sbi->s_inodes_used_count++;
			pmfs_inode_crawl(sb, bm, pi);
		}
		return;
	}

	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		pmfs_inode_table_crawl_recursive(sb, bm,
			le64_to_cpu(node[i]), height - 1, btype);
	}
}

static int pmfs_alloc_insert_blocknode_map(struct super_block *sb,
	unsigned long low, unsigned long high)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i, *next_i;
	struct pmfs_blocknode *free_blocknode= NULL;
	unsigned long num_blocks = 0;
	struct pmfs_blocknode *curr_node;
	int errval = 0;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;

	//num_blocks = pmfs_get_numblocks(btype);

	new_block_low = low;
	new_block_high = high;
	num_blocks = high - low + 1;

	list_for_each_entry(i, head, link) {
		if (i->link.next == head) {
			next_i = NULL;
			next_block_low = sbi->block_end;
		} else {
			next_i = list_entry(i->link.next, typeof(*i), link);
			next_block_low = next_i->block_low;
		}


		if (new_block_high >= next_block_low) {
			/* Does not fit - skip to next blocknode */
			continue;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1)))
		{
			/* Fill the gap completely */
			if (next_i) {
				i->block_high = next_i->block_high;
				rb_erase(&next_i->node,
					&sbi->block_inuse_tree);
				list_del(&next_i->link);
				free_blocknode = next_i;
			} else {
				i->block_high = new_block_high;
			}
			found = 1;
			break;
		}

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns to left */
			i->block_high = new_block_high;
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1))) {
			/* Aligns to right */
			if (next_i) {
				/* right node exist */
				next_i->block_low = new_block_low;
			} else {
				/* right node does NOT exist */
				curr_node = pmfs_alloc_block_node(sb);
				PMFS_ASSERT(curr_node);
				if (curr_node == NULL) {
					errval = -ENOSPC;
					break;
				}
				curr_node->block_low = new_block_low;
				curr_node->block_high = new_block_high;
				list_add(&curr_node->link, &i->link);
				pmfs_insert_blocknode_blocktree(sbi, curr_node);
			}
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns somewhere in the middle */
			curr_node = pmfs_alloc_block_node(sb);
			PMFS_ASSERT(curr_node);
			if (curr_node == NULL) {
				errval = -ENOSPC;
				break;
			}
			curr_node->block_low = new_block_low;
			curr_node->block_high = new_block_high;
			list_add(&curr_node->link, &i->link);
			pmfs_insert_blocknode_blocktree(sbi, curr_node);
			found = 1;
			break;
		}
	}
	
	if (found == 1) {
		sbi->num_free_blocks -= num_blocks;
	}	

	if (free_blocknode)
		pmfs_free_block_node(sb, free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}


	return errval;
}

static int __pmfs_build_blocknode_map(struct super_block *sb,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	unsigned long next = 1;
	unsigned long low = 0;

	while (1) {
		next = find_next_bit(bitmap, bsize, next);
		if (next == bsize)
			break;
		low = next;
		next = find_next_zero_bit(bitmap, bsize, next);
		if (pmfs_alloc_insert_blocknode_map(sb, low << scale ,
				(next << scale) - 1)) {
			printk("PMFS: Error could not insert 0x%lx-0x%lx\n",
				low << scale, ((next << scale) - 1));
		}
		if (next == bsize)
			break;
	}
	return 0;
}
	
static void pmfs_build_blocknode_map(struct super_block *sb,
							struct scan_bitmap *bm)
{
	__pmfs_build_blocknode_map(sb, bm->bitmap_4k, bm->bitmap_4k_size * 8,
		PAGE_SHIFT - 12);
	__pmfs_build_blocknode_map(sb, bm->bitmap_2M, bm->bitmap_2M_size * 8,
		PAGE_SHIFT_2M - 12);
	__pmfs_build_blocknode_map(sb, bm->bitmap_1G, bm->bitmap_1G_size * 8,
		PAGE_SHIFT_1G - 12);
}

static void free_bm(struct scan_bitmap *bm)
{
	kfree(bm->bitmap_4k);
	kfree(bm->bitmap_2M);
	kfree(bm->bitmap_1G);
	kfree(bm);
}

static struct scan_bitmap *alloc_bm(unsigned long initsize)
{
	struct scan_bitmap *bm;

	bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
	if (!bm)
		return NULL;

	bm->bitmap_4k_size = (initsize >> (PAGE_SHIFT + 0x3)) + 1;
	bm->bitmap_2M_size = (initsize >> (PAGE_SHIFT_2M + 0x3)) + 1;
	bm->bitmap_1G_size = (initsize >> (PAGE_SHIFT_1G + 0x3)) + 1;

	/* Alloc memory to hold the block alloc bitmap */
	bm->bitmap_4k = kzalloc(bm->bitmap_4k_size, GFP_KERNEL);
	bm->bitmap_2M = kzalloc(bm->bitmap_2M_size, GFP_KERNEL);
	bm->bitmap_1G = kzalloc(bm->bitmap_1G_size, GFP_KERNEL);

	if (!bm->bitmap_4k || !bm->bitmap_2M || !bm->bitmap_1G) {
		free_bm(bm);
		return NULL;
	}

	return bm;
}

int pmfs_setup_blocknode_map(struct super_block *sb)
{
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	pmfs_journal_t *journal = pmfs_get_journal(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct scan_bitmap *bm;
	unsigned long initsize = le64_to_cpu(super->s_size);
	bool value = false;

	mutex_init(&sbi->inode_table_mutex);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);

	value = pmfs_can_skip_full_scan(sb);
	if (value) {
		pmfs_dbg_verbose("PMFS: Skipping full scan of inodes...\n");
		return 0;
	}

	bm = alloc_bm(initsize);
	if (!bm)
		return -ENOMEM;

	/* Clearing the datablock inode */
	pmfs_clear_datablock_inode(sb);

	pmfs_inode_table_crawl_recursive(sb, bm, le64_to_cpu(pi->root),
						pi->height, pi->i_blk_type);

	/* Reserving tow inodes - Inode 0 and Inode for datablock */
	sbi->s_free_inodes_count = sbi->s_inodes_count -  
		(sbi->s_inodes_used_count + 2);
	
	/* set the block 0 as this is used */
	sbi->s_free_inode_hint = PMFS_FREE_INODE_HINT_START;

	/* initialize the num_free_blocks to */
	sbi->num_free_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);
	pmfs_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);

	pmfs_build_blocknode_map(sb, bm);

	free_bm(bm);

	return 0;
}


/************************** CoolFS recovery ****************************/

struct kmem_cache *pmfs_header_cachep;

struct pmfs_inode_info_header *pmfs_alloc_header(struct super_block *sb,
	u16 i_mode)
{
	struct pmfs_inode_info_header *p;
	p = (struct pmfs_inode_info_header *)
		kmem_cache_alloc(pmfs_header_cachep, GFP_NOFS);

	if (!p)
		BUG();

	p->root = 0;
	p->height = 0;
	p->log_pages = 0;
	p->dir_tree = RB_ROOT;
	p->i_mode = i_mode;

	atomic64_inc(&header_alloc);
	return p;
}

static void pmfs_free_header(struct super_block *sb,
	struct pmfs_inode_info_header *sih)
{
	kmem_cache_free(pmfs_header_cachep, sih);
	atomic64_inc(&header_free);
}

static int pmfs_increase_header_tree_height(struct super_block *sb,
	u32 new_height)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	u32 height = sbi->height;
	__le64 *root, prev_root = sbi->root;
	unsigned long page_addr;
	int errval = 0;

	pmfs_dbg_verbose("increasing tree height %x:%x, prev root 0x%llx\n",
						height, new_height, prev_root);
	while (height < new_height) {
		/* allocate the meta block */
		errval = pmfs_new_meta_block(sb, &page_addr, 1, 1);
		if (errval) {
			pmfs_err(sb, "failed to increase btree height\n");
			break;
		}
		root = (__le64 *)DRAM_ADDR(page_addr);
		root[0] = prev_root;
		prev_root = page_addr;
		height++;
	}
	sbi->root = prev_root;
	sbi->height = height;
	pmfs_dbg_verbose("increased tree height, new root 0x%llx\n",
							prev_root);
	return errval;
}

static int pmfs_inode_alive(struct super_block *sb,
	struct pmfs_inode_info_header *sih, struct pmfs_inode **return_pi)
{
	struct pmfs_inode *pi;

	if (sih->ino && sih->pi_addr) {
		pi = (struct pmfs_inode *)pmfs_get_block(sb, sih->pi_addr);
		if (pi->valid) {
			*return_pi = pi;
			return 1;
		}
	}

	return 0;
}

static int recursive_truncate_header_tree(struct super_block *sb,
	struct pmfs_inode *inode_table,
	struct pmfs_inode_info_header *inode_table_sih,
	__le64 block, u32 height, unsigned long first_blocknr)
{
	struct pmfs_inode_info_header *sih;
	struct pmfs_inode *pi = NULL;
	unsigned long first_blk, page_addr;
	unsigned int node_bits, first_index, last_index, i;
	__le64 *node;
	unsigned int freed = 0;

	node = (__le64 *)block;

	node_bits = (height - 1) * META_BLK_SHIFT;

	first_index = first_blocknr >> node_bits;
	last_index = (1 << META_BLK_SHIFT) - 1;

	if (height == 1) {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			sih = (struct pmfs_inode_info_header *)node[i];
			if (pmfs_inode_alive(sb, sih, &pi))
				pmfs_append_alive_inode_entry(sb, inode_table,
						pi, sih, inode_table_sih);
			pmfs_free_dram_resource(sb, sih);
			pmfs_free_header(sb, sih);
			node[i] = 0;
			freed++;
		}
	} else {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			freed += recursive_truncate_header_tree(sb,
					inode_table, inode_table_sih,
					DRAM_ADDR(node[i]), height - 1,
					first_blk);
			/* Freeing the meta-data block */
			page_addr = node[i];
			pmfs_free_meta_block(sb, page_addr);
		}
	}
	return freed;
}

unsigned int pmfs_free_header_tree(struct super_block *sb)
{
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	struct pmfs_inode_info_header *sih, *inode_table_sih;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = NULL;
	unsigned long root = sbi->root;
	unsigned long first_blocknr;
	unsigned int freed;

	if (!root)
		return 0;

	inode_table_sih = pmfs_alloc_header(sb, 0);

	if (sbi->height == 0) {
		sih = (struct pmfs_inode_info_header *)root;
		if (pmfs_inode_alive(sb, sih, &pi))
			pmfs_append_alive_inode_entry(sb, inode_table, pi,
					sih, inode_table_sih);
		pmfs_free_dram_resource(sb, sih);
		pmfs_free_header(sb, (void *)root);
		freed = 1;
	} else {
		first_blocknr = 0;

		freed = recursive_truncate_header_tree(sb, inode_table,
				inode_table_sih, DRAM_ADDR(root), sbi->height,
				first_blocknr);
		first_blocknr = root;
		pmfs_free_meta_block(sb, first_blocknr);
	}

	pmfs_free_header(sb, inode_table_sih);
	pmfs_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);
	sbi->root = sbi->height = 0;
	pmfs_dbg("%s: freed %u\n", __func__, freed);
	return freed;
}

static int recursive_assign_info_header(struct super_block *sb,
	unsigned long blocknr, unsigned long ino,
	struct pmfs_inode_info_header *sih,
	__le64 block, u32 height)
{
	int errval;
	unsigned int meta_bits = META_BLK_SHIFT, node_bits;
	__le64 *node;
	unsigned long index;
	unsigned long new_page;

	node = (__le64 *)block;
	node_bits = (height - 1) * meta_bits;
	index = blocknr >> node_bits;

	pmfs_dbg_verbose("%s: node 0x%llx, height %u, index %lu\n",
				__func__, block, height, index);

	if (height == 1) {
		if (node[index]) {
			struct pmfs_inode_info_header *old_sih;
			old_sih = (struct pmfs_inode_info_header *)node[index];
			if (old_sih->root || old_sih->height)
				pmfs_dbg("%s: node %lu %lu exists! 0x%llx, "
					"0x%lx\n", __func__, index, ino,
					node[index], (unsigned long)sih);
			pmfs_free_header(sb, old_sih);
		}
		node[index] = (unsigned long)sih;
	} else {
		if (node[index] == 0) {
			/* allocate the meta block */
			errval = pmfs_new_meta_block(sb, &new_page, 1, 1);
			if (errval) {
				pmfs_dbg("alloc meta blk failed\n");
				goto fail;
			}
			node[index] = new_page;
		}

		blocknr = blocknr & ((1 << node_bits) - 1);
		errval = recursive_assign_info_header(sb, blocknr, ino, sih,
			DRAM_ADDR(node[index]), height - 1);
		if (errval < 0)
			goto fail;
	}
	errval = 0;
fail:
	return errval;
}

/* Ino is divided by INODE_BITS */
int pmfs_assign_info_header(struct super_block *sb, unsigned long ino,
	struct pmfs_inode_info_header *sih, int multithread)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long max_blocks;
	unsigned int height;
	unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
	unsigned long total_blocks;
	int errval;
	unsigned long flags;

	if (multithread)
		spin_lock_irqsave(&sbi->header_tree_lock, flags);

	pmfs_dbg_verbose("assign_header root 0x%lx height %d ino %lu, %p\n",
			sbi->root, sbi->height, ino, sih);

	height = sbi->height;

	blk_shift = height * meta_bits;

	max_blocks = 0x1UL << blk_shift;

	if (ino > max_blocks - 1) {
		/* B-tree height increases as a result of this allocation */
		total_blocks = ino >> blk_shift;
		while (total_blocks > 0) {
			total_blocks = total_blocks >> meta_bits;
			height++;
		}
		if (height > 3) {
			pmfs_dbg("[%s:%d] Max file size. Cant grow the file\n",
				__func__, __LINE__);
			errval = -ENOSPC;
			goto out;
		}
	}

	if (!sbi->root) {
		if (height == 0) {
			pmfs_dbg_verbose("Set root @%p\n", sih);
			sbi->root = (unsigned long)sih;
			sbi->height = height;
		} else {
			errval = pmfs_increase_header_tree_height(sb, height);
			if (errval) {
				pmfs_dbg("[%s:%d] failed: inc btree"
					" height\n", __func__, __LINE__);
				goto out;
			}
			errval = recursive_assign_info_header(sb, ino, ino,
					sih, DRAM_ADDR(sbi->root), sbi->height);
			if (errval < 0)
				goto out;
		}
	} else {
		if (height == 0) {
			pmfs_dbg("root @0x%lx but height is 0\n", sbi->root);
			errval = 0;
			goto out;
		}

		if (height > sbi->height) {
			errval = pmfs_increase_header_tree_height(sb, height);
			if (errval) {
				pmfs_dbg_verbose("Err: inc height %x:%x tot %lx"
					"\n", sbi->height, height, total_blocks);
				goto out;
			}
		}
		errval = recursive_assign_info_header(sb, ino, ino, sih,
						DRAM_ADDR(sbi->root), height);
		if (errval < 0)
			goto out;
	}
	if (sih)
		sih->ino = ino << PMFS_INODE_BITS;
	errval = 0;
out:
	if (multithread)
		spin_unlock_irqrestore(&sbi->header_tree_lock, flags);

	return errval;
}

static int pmfs_recover_inode(struct super_block *sb, struct pmfs_inode *pi,
	u64 pi_addr, struct scan_bitmap *bm, int cpuid,
	int multithread)
{
	struct pmfs_inode_info_header *sih;
	unsigned long pmfs_ino = pi->pmfs_ino;
	u64 ino = pmfs_ino << PMFS_INODE_BITS;

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		pmfs_dbg_verbose("This is thread %d, processing file %p, "
				"pmfs ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pmfs_ino, pi->log_head,
				pi->log_tail);
		sih = pmfs_alloc_header(sb, __le16_to_cpu(pi->i_mode));
		pmfs_rebuild_file_inode_tree(sb, pi_addr, sih, ino, bm);
		pmfs_assign_info_header(sb, pmfs_ino, sih, multithread);
		break;
	case S_IFDIR:
		pmfs_dbg_verbose("This is thread %d, processing dir %p, "
				"pmfs ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pmfs_ino, pi->log_head,
				pi->log_tail);
		sih = pmfs_alloc_header(sb, __le16_to_cpu(pi->i_mode));
		pmfs_rebuild_dir_inode_tree(sb, pi_addr, sih, ino, bm);
		pmfs_assign_info_header(sb, pmfs_ino, sih, multithread);
		break;
	case S_IFLNK:
		pmfs_dbg_verbose("This is thread %d, processing symlink %p, "
				"pmfs ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pmfs_ino, pi->log_head,
				pi->log_tail);
		/* No need to rebuild tree for symlink files */
		sih = pmfs_alloc_header(sb, __le16_to_cpu(pi->i_mode));
		sih->pi_addr = pi_addr;
		pmfs_assign_info_header(sb, pmfs_ino, sih, multithread);
		break;
	default:
		break;
	}

	return 0;
}

/*********************** Singlethread recovery *************************/

int *processed;

static void pmfs_inode_table_singlethread_crawl(struct super_block *sb,
	struct pmfs_inode *inode_table, struct scan_bitmap *bm)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_alive_inode_entry *entry = NULL;
	size_t size = sizeof(struct pmfs_alive_inode_entry);
	struct pmfs_inode *pi;
	u64 curr_p = inode_table->log_head;

	pmfs_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	pmfs_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, inode_table->log_tail);

	if (curr_p == 0 && inode_table->log_tail == 0)
		return;

	while (curr_p != inode_table->log_tail) {
		if (is_last_entry(curr_p, size, 0))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			pmfs_err(sb, "Alive inode log reaches NULL!\n");
			BUG();
		}

		if (bm) {
			sbi->s_inodes_used_count++;
			sbi->s_inodes_used_count++;
		}

		entry = (struct pmfs_alive_inode_entry *)pmfs_get_block(sb,
								curr_p);

		pi = (struct pmfs_inode *)pmfs_get_block(sb, entry->pi_addr);
		pmfs_recover_inode(sb, pi, entry->pi_addr,
						bm, smp_processor_id(), 0);
		processed[smp_processor_id()]++;
		curr_p += size;
	}

	pmfs_free_inode_log(sb, inode_table);
	inode_table->log_head = inode_table->log_tail = 0;
	pmfs_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);

	return;
}

int pmfs_singlethread_recovery(struct super_block *sb, struct scan_bitmap *bm)
{
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	int cpus = num_online_cpus();
	int i, total = 0;
	int ret = 0;

	processed = kzalloc(cpus * sizeof(int), GFP_KERNEL);
	if (!processed)
		return -ENOMEM;

	pmfs_inode_table_singlethread_crawl(sb, inode_table, bm);

	for (i = 0; i < cpus; i++) {
		total += processed[i];
		pmfs_dbg_verbose("CPU %d: recovered %d\n", i, processed[i]);
	}

	kfree(processed);
	pmfs_dbg("Singlethread total recovered %d\n", total);
	return ret;
}

/*********************** Multithread recovery *************************/

struct task_ring {
	u64 tasks[512];
	int id;
	int enqueue;
	int dequeue;
	int processed;
	wait_queue_head_t assign_wq;
};

static inline void init_ring(struct task_ring *ring, int id)
{
	ring->id = id;
	ring->enqueue = ring->dequeue = 0;
	ring->processed = 0;
	init_waitqueue_head(&ring->assign_wq);
}

static inline bool task_ring_is_empty(struct task_ring *ring)
{
	return ring->enqueue == ring->dequeue;
}

static inline bool task_ring_is_full(struct task_ring *ring)
{
	return (ring->enqueue + 1) % 512 == ring->dequeue;
}

static inline void task_ring_enqueue(struct task_ring *ring, u64 pi_addr)
{
	pmfs_dbg_verbose("Enqueue at %d\n", ring->enqueue);
	if (ring->tasks[ring->enqueue])
		pmfs_dbg("%s: ERROR existing entry %llu\n", __func__,
				ring->tasks[ring->enqueue]);
	ring->tasks[ring->enqueue] = pi_addr;
	ring->enqueue = (ring->enqueue + 1) % 512;
}

static inline struct pmfs_inode *task_ring_dequeue(struct super_block *sb,
	struct task_ring *ring,	u64 *pi_addr)
{
	struct pmfs_inode *pi;

	*pi_addr = ring->tasks[ring->dequeue];
	pi = (struct pmfs_inode *)pmfs_get_block(sb, *pi_addr);

	if (!pi)
		BUG();

	ring->tasks[ring->dequeue] = 0;
	ring->dequeue = (ring->dequeue + 1) % 512;
	ring->processed++;

	return pi;
}

struct scan_bitmap *recovery_bm = NULL;
static struct task_struct **threads;
static struct task_ring *task_rings;
wait_queue_head_t finish_wq;

static int thread_func(void *data)
{
	struct super_block *sb = data;
	struct pmfs_inode *pi;
	int cpuid = smp_processor_id();
	struct task_ring *ring = &task_rings[cpuid];
	u64 pi_addr = 0;

	while (!kthread_should_stop()) {
		while(!task_ring_is_empty(ring)) {
			pi = task_ring_dequeue(sb, ring, &pi_addr);
			pmfs_recover_inode(sb, pi, pi_addr, recovery_bm,
							cpuid, 1);
			wake_up_interruptible(&finish_wq);
		}
		wait_event_interruptible_timeout(ring->assign_wq, false,
							msecs_to_jiffies(1));
	}

	return 0;
}

static inline struct task_ring *get_free_ring(int cpus, struct task_ring *ring)
{
	int start;
	int i = 0;

	if (ring)
		start = ring->id + 1;
	else
		start = 0;

	while (i < cpus) {
		start = start % cpus;
		ring = &task_rings[start];
		if (!task_ring_is_full(ring))
			return ring;
		start++;
		i++;
	}

	return NULL;
}

static void pmfs_inode_table_multithread_crawl(struct super_block *sb,
	struct pmfs_inode *inode_table, struct scan_bitmap *bm, int cpus)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_alive_inode_entry *entry = NULL;
	size_t size = sizeof(struct pmfs_alive_inode_entry);
	struct task_ring *ring = NULL;
	u64 curr_p = inode_table->log_head;

	pmfs_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	pmfs_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, inode_table->log_tail);

	if (curr_p == 0 && inode_table->log_tail == 0)
		return;

	while (curr_p != inode_table->log_tail) {
		if (is_last_entry(curr_p, size, 0))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			pmfs_err(sb, "Alive inode log reaches NULL!\n");
			BUG();
		}

		if (bm) {
			sbi->s_inodes_used_count++;
			sbi->s_inodes_used_count++;
		}

		entry = (struct pmfs_alive_inode_entry *)pmfs_get_block(sb,
								curr_p);

		while ((ring = get_free_ring(cpus, ring)) == NULL) {
			wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
		}

		task_ring_enqueue(ring, entry->pi_addr);
		wake_up_interruptible(&ring->assign_wq);

		curr_p += size;
	}

	pmfs_free_inode_log(sb, inode_table);
	inode_table->log_head = inode_table->log_tail = 0;
	pmfs_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);

	return;
}

static void free_resources(void)
{
	kfree(threads);
	kfree(task_rings);
}

static int allocate_resources(struct super_block *sb, int cpus)
{
	int i;

	threads = kzalloc(cpus * sizeof(struct task_struct *), GFP_KERNEL);
	if (!threads)
		return -ENOMEM;

	task_rings = kzalloc(cpus * sizeof(struct task_ring), GFP_KERNEL);
	if (!task_rings) {
		kfree(threads);
		return -ENOMEM;
	}

	for (i = 0; i < cpus; i++) {
		init_ring(&task_rings[i], i);
		threads[i] = kthread_create(thread_func,
						sb, "recovery thread");
		kthread_bind(threads[i], i);
		wake_up_process(threads[i]);
	}

	init_waitqueue_head(&finish_wq);

	return 0;
}

static void wait_to_finish(int cpus)
{
	struct task_ring *ring;
	int total = 0;
	int i;

	for (i = 0; i < cpus; i++) {
		ring = &task_rings[i];
		while (!task_ring_is_empty(ring)) {
			wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
		}
	}

	for (i = 0; i < cpus; i++)
		kthread_stop(threads[i]);

	for (i = 0; i < cpus; i++) {
		ring = &task_rings[i];
		pmfs_dbg_verbose("Ring %d recovered %d\n", i, ring->processed);
		total += ring->processed;
	}

	pmfs_dbg("Multithread total recovered %d\n", total);
}

int pmfs_multithread_recovery(struct super_block *sb, struct scan_bitmap *bm)
{
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	int cpus;
	int ret;

	cpus = num_online_cpus();
	pmfs_dbg("%s: %d cpus\n", __func__, cpus);

	ret = allocate_resources(sb, cpus);
	if (ret)
		return ret;

	pmfs_inode_table_multithread_crawl(sb, inode_table, bm, cpus);

	wait_to_finish(cpus);
	free_resources();
	return ret;
}

/*********************** Recovery entrance *************************/

static inline void pmfs_assign_bogus_header_info(struct super_block *sb)
{
	pmfs_assign_info_header(sb, 0, NULL, 0);
}

int pmfs_inode_log_recovery(struct super_block *sb, int multithread)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	unsigned long initsize = le64_to_cpu(super->s_size);
	pmfs_journal_t *journal = pmfs_get_journal(sb);
	struct scan_bitmap *bm = NULL;
	bool value = false;
	int ret;
	timing_t recovery_time;

	PMFS_START_TIMING(recovery_t, recovery_time);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);

	/* FIXME: The whole part needs re-written if returns false */
	value = pmfs_can_skip_full_scan(sb);
	if (value) {
		pmfs_dbg("PMFS: Skipping build blocknode map\n");
	} else {
		pmfs_dbg("PMFS: build blocknode map\n");
		bm = alloc_bm(initsize);
		if (!bm)
			return -ENOMEM;

		recovery_bm = bm;
	}

	pmfs_dbg("%s\n", __func__);
	sbi->btype = PMFS_BLOCK_TYPE_4K;

	pmfs_assign_bogus_header_info(sb);
	if (multithread)
		ret = pmfs_multithread_recovery(sb, bm);
	else
		ret = pmfs_singlethread_recovery(sb, bm);

	if (bm) {
		/* Reserving tow inodes - Inode 0 and Inode for datablock */
		sbi->s_free_inodes_count = sbi->s_inodes_count -
				(sbi->s_inodes_used_count + 2);

		/* set the block 0 as this is used */
		sbi->s_free_inode_hint = PMFS_FREE_INODE_HINT_START;

		/* initialize the num_free_blocks to */
		sbi->num_free_blocks = ((unsigned long)
					(initsize) >> PAGE_SHIFT);
		pmfs_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);

		pmfs_build_blocknode_map(sb, bm);

		free_bm(bm);
	}

	PMFS_END_TIMING(recovery_t, recovery_time);
	return ret;
}
