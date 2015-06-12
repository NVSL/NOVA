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
#include "pmfs.h"

void pmfs_init_blockmap(struct super_block *sb, unsigned long init_used_size)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long num_used_block;
	struct pmfs_blocknode *blknode;

	num_used_block = (init_used_size + sb->s_blocksize - 1) >>
		sb->s_blocksize_bits;

	blknode = pmfs_alloc_block_node(sb);
	if (blknode == NULL)
		PMFS_ASSERT(0);
	blknode->block_low = sbi->block_start;
	blknode->block_high = sbi->block_start + num_used_block - 1;
	sbi->num_free_blocks -= num_used_block;
	pmfs_insert_blocknode_blocktree(sbi, blknode);
	list_add(&blknode->link, &sbi->block_inuse_head);
	pmfs_dbg_verbose("Add: %lu %lu\n", blknode->block_low,
					blknode->block_high);
}

static struct pmfs_blocknode *pmfs_next_blocknode(struct pmfs_blocknode *i,
						  struct list_head *head)
{
	if (list_is_last(&i->link, head))
		return NULL;
	return list_first_entry(&i->link, typeof(*i), link);
}

static inline void pmfs_free_dram_page(unsigned long page_addr)
{
	if ((page_addr & DRAM_BIT) == 0) {
		pmfs_dbg("Error: free a non-DRAM page? 0x%lx\n", page_addr);
		dump_stack();
		return;
	}

	pmfs_dbg_verbose("Free DRAM page 0x%lx\n", page_addr);

	if (page_addr & KMALLOC_BIT)
		kfree((void *)DRAM_ADDR(page_addr));
	else if (page_addr & VMALLOC_BIT)
		vfree((void *)DRAM_ADDR(page_addr));
	else
		free_page(DRAM_ADDR(page_addr));
}

static unsigned long pmfs_alloc_dram_page(struct super_block *sb,
	enum alloc_type type, int zero, int nosleep)
{
	unsigned long addr = 0;
	int flags;

	if (nosleep)
		flags = GFP_ATOMIC;
	else
		flags = GFP_KERNEL;

	switch (type) {
		case KMALLOC:
			if (zero == 1)
				addr = (unsigned long)kzalloc(PAGE_SIZE,
							flags);
			else
				addr = (unsigned long)kmalloc(PAGE_SIZE,
							flags);
			if (addr && addr == DRAM_ADDR(addr)) {
				addr |= DRAM_BIT | KMALLOC_BIT;
				pmfs_dbg_verbose("Kmalloc DRAM page 0x%lx\n", addr);
				break;
			}
			if (addr) {
				kfree((void *)addr);
				addr = 0;
			}
			/* Fall through */
		case VMALLOC:
			if (zero == 1)
				addr = (unsigned long)vzalloc(flags);
			else
				addr = (unsigned long)vmalloc(flags);
			if (addr && addr == DRAM_ADDR(addr)) {
				addr |= DRAM_BIT | VMALLOC_BIT;
				pmfs_dbg_verbose("vmalloc DRAM page 0x%lx\n", addr);
				break;
			}
			if (addr) {
				vfree((void *)addr);
				addr = 0;
			}
			/* Fall through */
		case GETPAGE:
			if (zero == 1)
				addr = get_zeroed_page(flags);
			else
				addr = __get_free_page(flags);
			if (addr && addr == DRAM_ADDR(addr)) {
				addr |= DRAM_BIT | GETPAGE_BIT;
				pmfs_dbg_verbose("Get DRAM page 0x%lx\n", addr);
				break;
			}
			if (addr) {
				free_page(addr);
				addr = 0;
			}
			/* Fall through */
		default:
			break;
	}

	if (addr == 0)
		BUG();

	return addr;
}

static int pmfs_rbtree_compare_blocknode(struct pmfs_blocknode *curr,
	unsigned long new_block_low)
{
	if (new_block_low < curr->block_low)
		return -1;
	if (new_block_low > curr->block_high)
		return 1;

	return 0;
}

static struct pmfs_blocknode *pmfs_find_blocknode(struct pmfs_sb_info *sbi,
	unsigned long new_block_low, unsigned long *step, int block_tree)
{
	struct pmfs_blocknode *curr;
	struct rb_node *temp;
	int compVal;

	if (block_tree)
		temp = sbi->block_inuse_tree.rb_node;
	else
		temp = sbi->inode_inuse_tree.rb_node;

	while (temp) {
		curr = container_of(temp, struct pmfs_blocknode, node);
		compVal = pmfs_rbtree_compare_blocknode(curr, new_block_low);
		(*step)++;

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			return curr;
		}
	}

	return NULL;
}

inline struct pmfs_blocknode *
pmfs_find_blocknode_blocktree(struct pmfs_sb_info *sbi,
	unsigned long new_block_low, unsigned long *step)
{
	return pmfs_find_blocknode(sbi, new_block_low, step, 1);
}

inline struct pmfs_blocknode *
pmfs_find_blocknode_inodetree(struct pmfs_sb_info *sbi,
	unsigned long new_block_low, unsigned long *step)
{
	return pmfs_find_blocknode(sbi, new_block_low, step, 0);
}

static int pmfs_insert_blocknode(struct pmfs_sb_info *sbi,
	struct pmfs_blocknode *new_node, int block_tree)
{
	struct pmfs_blocknode *curr;
	struct rb_node **temp, *parent;
	int compVal;

	if (block_tree)
		temp = &(sbi->block_inuse_tree.rb_node);
	else
		temp = &(sbi->inode_inuse_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct pmfs_blocknode, node);
		compVal = pmfs_rbtree_compare_blocknode(curr,
					new_node->block_low);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			pmfs_dbg("%s: entry %lu - %lu already exists\n",
				__func__, new_node->block_low,
				new_node->block_high);
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->node, parent, temp);

	if (block_tree)
		rb_insert_color(&new_node->node, &sbi->block_inuse_tree);
	else
		rb_insert_color(&new_node->node, &sbi->inode_inuse_tree);
	return 0;
}

inline int pmfs_insert_blocknode_blocktree(struct pmfs_sb_info *sbi,
	struct pmfs_blocknode *new_node)
{
	return pmfs_insert_blocknode(sbi, new_node, 1);
}

inline int pmfs_insert_blocknode_inodetree(struct pmfs_sb_info *sbi,
	struct pmfs_blocknode *new_node)
{
	return pmfs_insert_blocknode(sbi, new_node, 0);
}

/* Caller must hold the super_block lock.  If start_hint is provided, it is
 * only valid until the caller releases the super_block lock. */
static void __pmfs_free_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype, struct pmfs_blocknode **start_hint,
	int log_block)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long num_blocks = 0;
	struct pmfs_blocknode *i = NULL;
	struct pmfs_blocknode *free_blocknode= NULL;
	struct pmfs_blocknode *curr_node;
	unsigned long step = 0;

	if (num <= 0) {
		pmfs_dbg("%s ERROR: free %d\n", __func__, num);
		return;
	}

	num_blocks = pmfs_get_numblocks(btype) * num;
	new_block_low = blocknr;
	new_block_high = blocknr + num_blocks - 1;

	BUG_ON(list_empty(head));

	pmfs_dbg_verbose("Free: %lu - %lu\n", new_block_low, new_block_high);

	if (start_hint && *start_hint &&
	    new_block_low >= (*start_hint)->block_low) {
		i = *start_hint;

		while (step <= 3) {
			if ((new_block_low >= i->block_low) &&
				(new_block_high <= i->block_high)) {
				goto Found;
			}

			if (new_block_high < i->block_low)
				break;

			if (i->link.next == head)
				break;
			else
				i = list_entry(i->link.next, typeof(*i), link);
			step++;
		}
	}

	i = pmfs_find_blocknode_blocktree(sbi, new_block_low, &step);
	if (!i) {
		pmfs_dbg("%s ERROR: %lu - %lu not found\n", __func__,
				new_block_low, new_block_high);
		return;
	}

Found:
	if ((new_block_low == i->block_low) &&
		(new_block_high == i->block_high)) {
		/* fits entire datablock */
		if (start_hint)
			*start_hint = pmfs_next_blocknode(i, head);
		rb_erase(&i->node, &sbi->block_inuse_tree);
		list_del(&i->link);
		free_blocknode = i;
		sbi->num_blocknode_block--;
		sbi->num_free_blocks += num_blocks;
		goto block_found;
	}
	if ((new_block_low == i->block_low) &&
		(new_block_high < i->block_high)) {
		/* Aligns left */
		i->block_low = new_block_high + 1;
		sbi->num_free_blocks += num_blocks;
		if (start_hint)
			*start_hint = i;
		goto block_found;
	}
	if ((new_block_low > i->block_low) &&
		(new_block_high == i->block_high)) {
		/* Aligns right */
		i->block_high = new_block_low - 1;
		sbi->num_free_blocks += num_blocks;
		if (start_hint)
			*start_hint = pmfs_next_blocknode(i, head);
		goto block_found;
	}
	if ((new_block_low > i->block_low) &&
		(new_block_high < i->block_high)) {
		/* Aligns somewhere in the middle */
		curr_node = pmfs_alloc_block_node(sb);
		PMFS_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block*/
			goto block_found;
		}
		curr_node->block_low = new_block_high + 1;
		curr_node->block_high = i->block_high;
		i->block_high = new_block_low - 1;
		pmfs_insert_blocknode_blocktree(sbi, curr_node);
		list_add(&curr_node->link, &i->link);
		sbi->num_free_blocks += num_blocks;
		if (start_hint)
			*start_hint = curr_node;
		goto block_found;
	}

	if (log_block)
		pmfs_error_mng(sb, "Unable to free log block %lu - %lu\n",
				 new_block_low, new_block_high);
	else
		pmfs_error_mng(sb, "Unable to free data block %lu - %lu\n",
				 new_block_low, new_block_high);
	pmfs_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->block_low, i->block_high);
//	dump_stack();

block_found:

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);
	free_steps += step;
}

void pmfs_free_meta_block(struct super_block *sb, unsigned long page_addr)
{
	timing_t free_time;

	PMFS_START_TIMING(free_meta_t, free_time);
	pmfs_dbg_verbose("Free meta block 0x%lx\n", page_addr);
	pmfs_free_dram_page(page_addr);
	PMFS_END_TIMING(free_meta_t, free_time);
	atomic64_inc(&meta_free);
}

void pmfs_free_cache_block(struct mem_addr *pair)
{
	timing_t free_time;

	PMFS_START_TIMING(free_cache_t, free_time);
	pmfs_dbg_verbose("Free cache block 0x%lx\n", pair->dram);
	pmfs_free_dram_page(pair->dram);
	pair->dram = 0;
	PMFS_END_TIMING(free_cache_t, free_time);
	atomic64_inc(&cache_free);
}

void pmfs_free_data_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype, struct pmfs_blocknode **start_hint,
	int needlock)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	timing_t free_time;

	pmfs_dbg_verbose("Free data block %lu\n", blocknr);
	PMFS_START_TIMING(free_data_t, free_time);
	if (needlock)
		mutex_lock(&sbi->s_lock);
	__pmfs_free_blocks(sb, blocknr, num, btype, start_hint, 0);
	free_data_pages += num;
	if (needlock)
		mutex_unlock(&sbi->s_lock);
	PMFS_END_TIMING(free_data_t, free_time);
}

void pmfs_free_log_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype, struct pmfs_blocknode **start_hint,
	int needlock)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	timing_t free_time;

	pmfs_dbg_verbose("Free log block %lu\n", blocknr);
	PMFS_START_TIMING(free_log_t, free_time);
	if (needlock)
		mutex_lock(&sbi->s_lock);
	__pmfs_free_blocks(sb, blocknr, num, btype, start_hint, 1);
	free_log_pages += num;
	if (needlock)
		mutex_unlock(&sbi->s_lock);
	PMFS_END_TIMING(free_log_t, free_time);
}

int pmfs_new_meta_block(struct super_block *sb, unsigned long *blocknr,
	int zero, int nosleep)
{
	unsigned long page_addr;
	timing_t alloc_time;

	PMFS_START_TIMING(new_meta_block_t, alloc_time);
	page_addr = pmfs_alloc_dram_page(sb, KMALLOC, zero, nosleep);
	if (page_addr == 0) {
		PMFS_END_TIMING(new_meta_block_t, alloc_time);
		return -EINVAL;
	}

	*blocknr = page_addr;
	pmfs_dbg_verbose("%s: 0x%lx\n", __func__, page_addr);
	PMFS_END_TIMING(new_meta_block_t, alloc_time);
	atomic64_inc(&meta_alloc);
	return 0;
}

unsigned long pmfs_new_cache_block(struct super_block *sb,
	int zero, int nosleep)
{
	unsigned long page_addr;
	timing_t alloc_time;

	PMFS_START_TIMING(new_cache_page_t, alloc_time);
	page_addr = pmfs_alloc_dram_page(sb, KMALLOC, zero, nosleep);
	if (page_addr == 0) {
		PMFS_END_TIMING(new_cache_page_t, alloc_time);
		pmfs_dbg("%s: allocation failed\n", __func__);
		BUG();
		return 0;
	}

	PMFS_END_TIMING(new_cache_page_t, alloc_time);
	atomic64_inc(&cache_alloc);
	return page_addr;
}

/* Return how many blocks allocated */
static int pmfs_new_blocks(struct super_block *sb, unsigned long *blocknr,
		unsigned int num, unsigned short btype, int zero, int log_page)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i, *next_i;
	struct pmfs_blocknode *free_blocknode= NULL;
	void *bp;
	unsigned long num_blocks = 0;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long step = 0;

	num_blocks = num * pmfs_get_numblocks(btype);
	if (num_blocks == 0)
		return -EINVAL;

	if (sbi->num_free_blocks < num_blocks)
		return -ENOSPC;

	mutex_lock(&sbi->s_lock);

	list_for_each_entry(i, head, link) {
		step++;
		if (i->link.next == head) {
			next_i = NULL;
			next_block_low = sbi->block_end;
		} else {
			next_i = list_entry(i->link.next, typeof(*i), link);
			next_block_low = next_i->block_low;
		}

		new_block_low = i->block_high + 1;
		new_block_high = new_block_low + num_blocks - 1;

		if (new_block_high >= next_block_low) {
			/* Superpage allocation must succeed */
			if (btype > 0)
				continue;

			/* Otherwise, allocate the hole */
			if (next_i) {
				i->block_high = next_i->block_high;
				rb_erase(&next_i->node,
					&sbi->block_inuse_tree);
				list_del(&next_i->link);
				free_blocknode = next_i;
				sbi->num_blocknode_block--;
			} else {
				i->block_high = new_block_high;
			}
			found = 1;
			num_blocks = next_block_low - new_block_low;
			break;
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
				sbi->num_blocknode_block--;
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
	}
	if (found == 1) {
		sbi->num_free_blocks -= num_blocks;
		if (log_page)
			alloc_log_pages += num_blocks;
		else
			alloc_data_pages += num_blocks;
	}	

	mutex_unlock(&sbi->s_lock);

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);

	if (found == 0) {
		alloc_steps += step;
		return -ENOSPC;
	}

	if (zero) {
		size_t size;
		bp = pmfs_get_block(sb, pmfs_get_block_off(sb, new_block_low, btype));
		pmfs_memunlock_block(sb, bp); //TBDTBD: Need to fix this
		if (btype == PMFS_BLOCK_TYPE_4K)
			size = 0x1 << 12;
		else if (btype == PMFS_BLOCK_TYPE_2M)
			size = 0x1 << 21;
		else
			size = 0x1 << 30;
		memset_nt(bp, 0, PAGE_SIZE * num_blocks);
		pmfs_memlock_block(sb, bp);
	}
	*blocknr = new_block_low;

	pmfs_dbg_verbose("Alloc %u data blocks %lu\n", num, *blocknr);
	alloc_steps += step;
	return num_blocks / pmfs_get_numblocks(btype);
}

inline int pmfs_new_data_blocks(struct super_block *sb, unsigned long *blocknr,
		unsigned int num, unsigned short btype, int zero)
{
	int allocated;
	timing_t alloc_time;
	PMFS_START_TIMING(new_data_blocks_t, alloc_time);
	allocated = pmfs_new_blocks(sb, blocknr, num, btype, zero, 0);
	PMFS_END_TIMING(new_data_blocks_t, alloc_time);
	return allocated;
}

inline int pmfs_new_log_blocks(struct super_block *sb, unsigned long *blocknr,
		unsigned int num, unsigned short btype, int zero)
{
	int allocated;
	timing_t alloc_time;
	PMFS_START_TIMING(new_log_blocks_t, alloc_time);
	allocated = pmfs_new_blocks(sb, blocknr, num, btype, zero, 1);
	PMFS_END_TIMING(new_log_blocks_t, alloc_time);
	return allocated;
}

unsigned long pmfs_count_free_blocks(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	return sbi->num_free_blocks; 
}
