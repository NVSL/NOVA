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

static struct kmem_cache *pmfs_bmentry_cachep;

static int __init init_bmentry_cache(void)
{
	pmfs_bmentry_cachep = kmem_cache_create("pmfs_bmentry_cache",
					       sizeof(struct multi_set_entry),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), NULL);
	if (pmfs_bmentry_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_bmentry_cache(void)
{
	kmem_cache_destroy(pmfs_bmentry_cachep);
}

static inline void set_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry;
	struct list_head *head = &(scan_bm->multi_set_head);

	if (test_and_set_bit(bit, scan_bm->bitmap) == 0)
		return;

	pmfs_dbgv("%s: type %d, bit %lu exists\n", __func__, type, bit);

	if (scan_bm->multi_set_exist && bit >= scan_bm->multi_set_low &&
			bit <= scan_bm->multi_set_high) {
		list_for_each_entry(entry, head, link) {
			if (entry->bit == bit) {
				entry->refcount++;
				return;
			}
		}
	}

	entry = kmem_cache_alloc(pmfs_bmentry_cachep, GFP_NOFS);
	if (!entry)
		PMFS_ASSERT(0);

	INIT_LIST_HEAD(&entry->link);
	entry->bit = bit;
	entry->refcount = 2;
	list_add_tail(&entry->link, head);
	if (scan_bm->multi_set_low > bit || scan_bm->multi_set_exist == 0)
		scan_bm->multi_set_low = bit;
	if (scan_bm->multi_set_high < bit || scan_bm->multi_set_exist == 0)
		scan_bm->multi_set_high = bit;
	scan_bm->multi_set_exist = 1;
}

static inline void delete_bm_entry(struct single_scan_bm *scan_bm,
	struct list_head *head, struct multi_set_entry *entry,
	enum bm_type type)
{
	pmfs_dbgv("%s: type %d, bit %lu, ref %d\n", __func__,
			type, entry->bit, entry->refcount);
	entry->refcount--;
	if (entry->refcount == 1) {
		list_del(&entry->link);
		/* FIXME: update multi_set_low/high */
		kmem_cache_free(pmfs_bmentry_cachep, entry);
		if (list_empty(head))
			scan_bm->multi_set_exist = 0;
	}
}

static inline void clear_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry, *next;
	struct list_head *head = &(scan_bm->multi_set_head);

	if (scan_bm->multi_set_exist && bit >= scan_bm->multi_set_low &&
			bit <= scan_bm->multi_set_high) {
		list_for_each_entry_safe(entry, next, head, link) {
			if (entry->bit == bit) {
				delete_bm_entry(scan_bm, head, entry, type);
				return;
			}
		}
	}

	clear_bit(bit, scan_bm->bitmap);
}

inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type)
{
	switch (type) {
		case BM_4K:
			set_scan_bm(bit, &bm->scan_bm_4K, type);
			break;
		case BM_2M:
			set_scan_bm(bit, &bm->scan_bm_2M, type);
			break;
		case BM_1G:
			set_scan_bm(bit, &bm->scan_bm_1G, type);
			break;
		default:
			break;
	}
}

inline void clear_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type)
{
	switch (type) {
		case BM_4K:
			clear_scan_bm(bit, &bm->scan_bm_4K, type);
			break;
		case BM_2M:
			clear_scan_bm(bit, &bm->scan_bm_2M, type);
			break;
		case BM_1G:
			clear_scan_bm(bit, &bm->scan_bm_1G, type);
			break;
		default:
			break;
	}
}

static int pmfs_insert_inodetree(struct super_block *sb,
	unsigned long pmfs_ino)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_blocknode *curr = NULL, *prev = NULL, *next = NULL;
	struct pmfs_blocknode *new_node;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(sbi->inode_inuse_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct pmfs_blocknode, node);
		compVal = pmfs_rbtree_compare_blocknode(curr, pmfs_ino);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			pmfs_dbg("%s: ino %lu exists in entry %lu - %lu\n",
				__func__, pmfs_ino, curr->block_low,
				curr->block_high);
			return 0;
		}
	}

	if (pmfs_ino < curr->block_low) {
		next = curr;
		prev = list_entry(curr->link.prev, struct pmfs_blocknode, link);
	} else {
		prev = curr;
		next = list_entry(curr->link.next, struct pmfs_blocknode, link);
	}

	if (pmfs_ino == curr->block_low - 1) {
		curr->block_low = pmfs_ino;
		if (prev && prev->block_high + 1 == pmfs_ino) {
			prev->block_high = curr->block_high;
			list_del(&curr->link);
			rb_erase(&curr->node,
					&sbi->inode_inuse_tree);
			sbi->num_blocknode_inode--;
		}
		return 0;
	}

	if (pmfs_ino == curr->block_high + 1) {
		curr->block_high = pmfs_ino;
		if (next && next->block_low - 1 == pmfs_ino) {
			curr->block_high = next->block_high;
			list_del(&next->link);
			rb_erase(&next->node,
					&sbi->inode_inuse_tree);
			sbi->num_blocknode_inode--;
		}
		return 0;
	}

	if (pmfs_ino < curr->block_low) {
		if (prev && prev->block_high + 1 == pmfs_ino) {
			prev->block_high = pmfs_ino;
			return 0;
		}
		goto insert;
	}

	if (pmfs_ino > curr->block_high) {
		if (next && next->block_low - 1 == pmfs_ino) {
			next->block_low = pmfs_ino;
			return 0;
		}
		goto insert;
	}

	pmfs_dbg("%s ERROR: ino %lu, entry %lu - %lu\n",
			__func__, pmfs_ino, curr->block_low,
			curr->block_high);
	return -EINVAL;

insert:
	new_node = pmfs_alloc_inode_node(sb);
	PMFS_ASSERT(new_node);
	new_node->block_low = new_node->block_high = pmfs_ino;
	list_add(&new_node->link, &prev->link);
	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, &sbi->inode_inuse_tree);
	sbi->num_blocknode_inode++;
	return 0;
}

static void pmfs_init_blockmap_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_blocknode_lowhigh *entry;
	struct pmfs_blocknode *blknode;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	unsigned long num_blocknode = 0;
	u64 curr_p;

	curr_p = pi->log_head;
	if (curr_p == 0)
		pmfs_dbg("%s: pi head is 0!\n", __func__);

	sbi->num_blocknode_block = 0;
	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			pmfs_dbg("%s: curr_p is NULL!\n", __func__);
			PMFS_ASSERT(0);
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

		num_blocknode++;
		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

	pmfs_dbg("%s: %lu blocknodes\n", __func__, num_blocknode);
	pmfs_free_inode_log(sb, pi);
}

static void pmfs_init_inode_list_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_INODELIST_INO);
	struct pmfs_blocknode_lowhigh *entry;
	struct pmfs_blocknode *blknode;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	unsigned long num_blocknode = 0;
	u64 curr_p;

	sbi->num_blocknode_inode = 0;
	curr_p = pi->log_head;
	if (curr_p == 0)
		pmfs_dbg("%s: pi head is 0!\n", __func__);

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			pmfs_dbg("%s: curr_p is NULL!\n", __func__);
			PMFS_ASSERT(0);
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

		num_blocknode++;
		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

	pmfs_dbg("%s: %lu inode nodes\n", __func__, num_blocknode);
	pmfs_free_inode_log(sb, pi);
}

static bool pmfs_can_skip_full_scan(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
	sbi->s_inodes_count = le64_to_cpu(super->s_inodes_count);
	sbi->s_free_inodes_count = le64_to_cpu(super->s_free_inodes_count);
	sbi->s_inodes_used_count = le64_to_cpu(super->s_inodes_used_count);
	sbi->s_free_inode_hint = le64_to_cpu(super->s_free_inode_hint);

	pmfs_init_blockmap_from_inode(sb);
	pmfs_init_inode_list_from_inode(sb);

	return true;
}

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
	pmfs_dbg_verbose("append entry alive inode %llu, pmfs inode 0x%llx "
			"@ 0x%llx\n",
			sih->ino, sih->pi_addr, curr_p);

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
	u64 curr_entry = 0;
	u64 temp_tail;

	/* Allocate log pages before save blocknode mappings */
	num_blocks = sbi->num_blocknode_block / BLOCKNODE_PER_PAGE;
	if (sbi->num_blocknode_block % BLOCKNODE_PER_PAGE)
		num_blocks++;

	allocated = pmfs_allocate_inode_log_pages(sb, pi, num_blocks,
						&new_block);
	if (allocated != num_blocks) {
		pmfs_dbg("Error saving blocknode mappings: %d\n", allocated);
		return;
	}

	/*
	 * save the total allocated blocknode mappings
	 * in super block
	 * No transaction is needed as we will recover the fields
	 * via DFS recovery
	 */
	super = pmfs_get_super(sb);

	pmfs_memunlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);

	super->s_wtime = cpu_to_le32(get_seconds());
	super->s_num_free_blocks = cpu_to_le64(sbi->num_free_blocks);
	super->s_inodes_count = cpu_to_le64(sbi->s_inodes_count);
	super->s_free_inodes_count = cpu_to_le64(sbi->s_free_inodes_count);
	super->s_inodes_used_count = cpu_to_le64(sbi->s_inodes_used_count);
	super->s_free_inode_hint = cpu_to_le64(sbi->s_free_inode_hint);

	pmfs_memlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);
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

	pmfs_dbg("%s: %lu blocknodes, step %d, pi head 0x%llx, tail 0x%llx\n",
		__func__, sbi->num_blocknode_block, step, pi->log_head,
		pi->log_tail);
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
	__pmfs_build_blocknode_map(sb, bm->scan_bm_4K.bitmap,
			bm->scan_bm_4K.bitmap_size * 8, PAGE_SHIFT - 12);
	__pmfs_build_blocknode_map(sb, bm->scan_bm_2M.bitmap,
			bm->scan_bm_2M.bitmap_size * 8, PAGE_SHIFT_2M - 12);
	__pmfs_build_blocknode_map(sb, bm->scan_bm_1G.bitmap,
			bm->scan_bm_1G.bitmap_size * 8, PAGE_SHIFT_1G - 12);
}

static void free_bm(struct scan_bitmap *bm)
{
	kfree(bm->scan_bm_4K.bitmap);
	kfree(bm->scan_bm_2M.bitmap);
	kfree(bm->scan_bm_1G.bitmap);
	kfree(bm);
	destroy_bmentry_cache();
}

static struct scan_bitmap *alloc_bm(unsigned long initsize)
{
	struct scan_bitmap *bm;

	bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
	if (!bm)
		return NULL;

	bm->scan_bm_4K.bitmap_size = (initsize >> (PAGE_SHIFT + 0x3)) + 1;
	bm->scan_bm_2M.bitmap_size = (initsize >> (PAGE_SHIFT_2M + 0x3)) + 1;
	bm->scan_bm_1G.bitmap_size = (initsize >> (PAGE_SHIFT_1G + 0x3)) + 1;

	/* Alloc memory to hold the block alloc bitmap */
	bm->scan_bm_4K.bitmap = kzalloc(bm->scan_bm_4K.bitmap_size,
							GFP_KERNEL);
	bm->scan_bm_2M.bitmap = kzalloc(bm->scan_bm_2M.bitmap_size,
							GFP_KERNEL);
	bm->scan_bm_1G.bitmap = kzalloc(bm->scan_bm_1G.bitmap_size,
							GFP_KERNEL);

	if (!bm->scan_bm_4K.bitmap || !bm->scan_bm_2M.bitmap ||
			!bm->scan_bm_1G.bitmap) {
		free_bm(bm);
		return NULL;
	}

	INIT_LIST_HEAD(&bm->scan_bm_4K.multi_set_head);
	INIT_LIST_HEAD(&bm->scan_bm_2M.multi_set_head);
	INIT_LIST_HEAD(&bm->scan_bm_1G.multi_set_head);

	if (init_bmentry_cache()) {
		free_bm(bm);
		return NULL;
	}

	return bm;
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
		PMFS_ASSERT(0);

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

int pmfs_recover_inode(struct super_block *sb, u64 pi_addr,
	struct scan_bitmap *bm, int cpuid, int multithread)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode_info_header *sih;
	struct pmfs_inode *pi;
	unsigned long pmfs_ino;

	pi = (struct pmfs_inode *)pmfs_get_block(sb, pi_addr);
	if (!pi)
		PMFS_ASSERT(0);

	if (pi->valid == 0)
		return 0;

	pmfs_ino = pi->pmfs_ino;
	if (bm && pmfs_ino != 1) {
		pmfs_insert_inodetree(sb, pmfs_ino);
		sbi->s_inodes_used_count++;
	}

	pmfs_dbg_verbose("%s: inode %lu, addr 0x%llx, valid %d, "
			"head 0x%llx, tail 0x%llx\n",
			__func__, pmfs_ino, pi_addr, pi->valid,
			pi->log_head, pi->log_tail);

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		pmfs_dbg_verbose("This is thread %d, processing file %p, "
				"pmfs ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pmfs_ino, pi->log_head,
				pi->log_tail);
		sih = pmfs_alloc_header(sb, __le16_to_cpu(pi->i_mode));
		pmfs_rebuild_file_inode_tree(sb, pi, pi_addr, sih, bm);
		pmfs_assign_info_header(sb, pmfs_ino, sih, multithread);
		break;
	case S_IFDIR:
		pmfs_dbg_verbose("This is thread %d, processing dir %p, "
				"pmfs ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pmfs_ino, pi->log_head,
				pi->log_tail);
		sih = pmfs_alloc_header(sb, __le16_to_cpu(pi->i_mode));
		pmfs_rebuild_dir_inode_tree(sb, pi, pi_addr, sih, bm);
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
		if (bm && pi->log_head) {
			BUG_ON(pi->log_head & (PAGE_SIZE - 1));
			set_bm(pi->log_head >> PAGE_SHIFT, bm, BM_4K);
		}
		pmfs_assign_info_header(sb, pmfs_ino, sih, multithread);
		break;
	default:
		break;
	}

	return 0;
}

/*********************** DFS recovery *************************/

int pmfs_dfs_recovery(struct super_block *sb, struct scan_bitmap *bm)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi;
	u64 root_addr = PMFS_ROOT_INO_START;
	int ret;

	/* Initialize inuse inode list */
	if (pmfs_init_inode_inuse_list(sb) < 0)
		return -EINVAL;

	/* Handle special inodes */
	pi = pmfs_get_inode_by_ino(sb, PMFS_INODELIST_INO);
	pi->log_head = pi->log_tail = 0;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	pi = pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	pi->log_head = pi->log_tail = 0;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	pi = pmfs_get_inode_table(sb);
	pi->log_head = pi->log_tail = 0;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	pi = pmfs_get_inode_by_ino(sb, PMFS_LITEJOURNAL_INO);
	if (pi->log_head)
		set_bm(pi->log_head >> PAGE_SHIFT, bm, BM_4K);

	/* Start from the root iode */
	ret = pmfs_recover_inode(sb, root_addr, bm, smp_processor_id(), 0);

	pmfs_dbg("DFS recovery total recovered %lu\n",
				sbi->s_inodes_used_count);
	return ret;
}

/*********************** Singlethread recovery *************************/

int *processed;

static void pmfs_inode_table_singlethread_crawl(struct super_block *sb,
	struct pmfs_inode *inode_table)
{
	struct pmfs_alive_inode_entry *entry = NULL;
	size_t size = sizeof(struct pmfs_alive_inode_entry);
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
			PMFS_ASSERT(0);
		}

		entry = (struct pmfs_alive_inode_entry *)pmfs_get_block(sb,
								curr_p);

		pmfs_recover_inode(sb, entry->pi_addr, NULL,
						smp_processor_id(), 0);
		processed[smp_processor_id()]++;
		curr_p += size;
	}

	pmfs_free_inode_log(sb, inode_table);
	inode_table->log_head = inode_table->log_tail = 0;
	pmfs_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);

	return;
}

int pmfs_singlethread_recovery(struct super_block *sb)
{
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	int cpus = num_online_cpus();
	int i, total = 0;
	int ret = 0;

	processed = kzalloc(cpus * sizeof(int), GFP_KERNEL);
	if (!processed)
		return -ENOMEM;

	pmfs_inode_table_singlethread_crawl(sb, inode_table);

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

static inline u64 task_ring_dequeue(struct super_block *sb,
	struct task_ring *ring)
{
	u64 pi_addr = 0;

	pi_addr = ring->tasks[ring->dequeue];

	if (pi_addr == 0)
		PMFS_ASSERT(0);

	ring->tasks[ring->dequeue] = 0;
	ring->dequeue = (ring->dequeue + 1) % 512;
	ring->processed++;

	return pi_addr;
}

static struct task_struct **threads;
static struct task_ring *task_rings;
wait_queue_head_t finish_wq;

static int thread_func(void *data)
{
	struct super_block *sb = data;
	int cpuid = smp_processor_id();
	struct task_ring *ring = &task_rings[cpuid];
	u64 pi_addr = 0;

	while (!kthread_should_stop()) {
		while(!task_ring_is_empty(ring)) {
			pi_addr = task_ring_dequeue(sb, ring);
			pmfs_recover_inode(sb, pi_addr, NULL,
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
	struct pmfs_inode *inode_table, int cpus)
{
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
			PMFS_ASSERT(0);
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

int pmfs_multithread_recovery(struct super_block *sb)
{
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	int cpus;
	int ret;

	cpus = num_online_cpus();
	pmfs_dbg("%s: %d cpus\n", __func__, cpus);

	ret = allocate_resources(sb, cpus);
	if (ret)
		return ret;

	pmfs_inode_table_multithread_crawl(sb, inode_table, cpus);

	wait_to_finish(cpus);
	free_resources();
	return ret;
}

/*********************** Recovery entrance *************************/

static inline void pmfs_assign_bogus_header_info(struct super_block *sb)
{
	pmfs_assign_info_header(sb, 0, NULL, 0);
}

static void pmfs_rebuild_superblock_info(struct super_block *sb,
	pmfs_journal_t *journal, unsigned long initsize,
	struct scan_bitmap *bm)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);

	/* initialize the num_free_blocks to */
	sbi->num_free_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);
	pmfs_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);

	/* Minus the block for lite journaling */
	sbi->s_inodes_count = (sbi->num_free_blocks - 1) <<
			(pmfs_inode_blk_shift(pi) - PMFS_INODE_BITS);

	pmfs_build_blocknode_map(sb, bm);

	/* Reserving basic inodes */
	sbi->s_free_inodes_count = sbi->s_inodes_count -
		(sbi->s_inodes_used_count + PMFS_FREE_INODE_HINT_START);

	/* set the block 0 as this is used */
	sbi->s_free_inode_hint = PMFS_FREE_INODE_HINT_START;
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

	value = pmfs_can_skip_full_scan(sb);
	if (value) {
		pmfs_dbg("PMFS: Skipping build blocknode map\n");
	} else {
		pmfs_dbg("PMFS: build blocknode map\n");
		bm = alloc_bm(initsize);
		if (!bm)
			return -ENOMEM;
	}

	pmfs_dbgv("%s\n", __func__);
	sbi->btype = PMFS_BLOCK_TYPE_4K;

	pmfs_assign_bogus_header_info(sb);
	if (bm) {
		sbi->s_inodes_used_count = 0;
		ret = pmfs_dfs_recovery(sb, bm);
	} else {
		if (multithread)
			ret = pmfs_multithread_recovery(sb);
		else
			ret = pmfs_singlethread_recovery(sb);
	}

	if (bm) {
		pmfs_rebuild_superblock_info(sb, journal, initsize, bm);
		free_bm(bm);
	}

	PMFS_END_TIMING(recovery_t, recovery_time);
	return ret;
}
