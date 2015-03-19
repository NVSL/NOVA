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

	blknode = pmfs_alloc_blocknode(sb);
	if (blknode == NULL)
		PMFS_ASSERT(0);
	blknode->block_low = sbi->block_start;
	blknode->block_high = sbi->block_start + num_used_block - 1;
	sbi->num_free_blocks -= num_used_block;
	list_add(&blknode->link, &sbi->block_inuse_head);
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
		pmfs_dbg("Error: free a non-DRAM page? 0x%lx", page_addr);
		dump_stack();
	}

	if (page_addr & KMALLOC_BIT)
		kfree((void *)DRAM_ADDR(page_addr));
	else
		free_page(DRAM_ADDR(page_addr));
}

static unsigned long pmfs_alloc_dram_page(struct super_block *sb, int zero)
{
	unsigned long addr = 0;

	/* kmalloc is faster than get_free_page */
	if (zero == 1)
		addr = (unsigned long)kzalloc(PAGE_SIZE, GFP_KERNEL);
	else
		addr = (unsigned long)kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (addr && addr == DRAM_ADDR(addr)) {
		addr |= DRAM_BIT | KMALLOC_BIT;
		return addr;
	}

	/* Needs to align to PAGE_SIZE */
	if (addr)
		kfree((void *)addr);

	if (zero == 1)
		addr = get_zeroed_page(GFP_KERNEL);
	else
		addr = __get_free_page(GFP_KERNEL);

	if (addr == 0 || addr != DRAM_ADDR(addr))
		BUG();

	addr |= DRAM_BIT | GETPAGE_BIT;
	return addr;
}

/* Caller must hold the super_block lock.  If start_hint is provided, it is
 * only valid until the caller releases the super_block lock. */
void __pmfs_free_block(struct super_block *sb, unsigned long blocknr,
		unsigned short btype, struct pmfs_blocknode **start_hint,
		int log_block)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long num_blocks = 0;
	struct pmfs_blocknode *i;
	struct pmfs_blocknode *free_blocknode= NULL;
	struct pmfs_blocknode *curr_node;
	unsigned long step = 0;

	num_blocks = pmfs_get_numblocks(btype);
	new_block_low = blocknr;
	new_block_high = blocknr + num_blocks - 1;

	BUG_ON(list_empty(head));

	if (start_hint && *start_hint &&
	    new_block_low >= (*start_hint)->block_low)
		i = *start_hint;
	else
		i = list_first_entry(head, typeof(*i), link);

	list_for_each_entry_from(i, head, link) {
		step++;
		if (new_block_low > i->block_high) {
			/* skip to next blocknode */
			continue;
		}

		if ((new_block_low == i->block_low) &&
			(new_block_high == i->block_high)) {
			/* fits entire datablock */
			if (start_hint)
				*start_hint = pmfs_next_blocknode(i, head);
			list_del(&i->link);
			free_blocknode = i;
			sbi->num_blocknode_allocated--;
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
			curr_node = pmfs_alloc_blocknode(sb);
			PMFS_ASSERT(curr_node);
			if (curr_node == NULL) {
				/* returning without freeing the block*/
				goto block_found;
			}
			curr_node->block_low = new_block_high + 1;
			curr_node->block_high = i->block_high;
			i->block_high = new_block_low - 1;
			list_add(&curr_node->link, &i->link);
			sbi->num_free_blocks += num_blocks;
			if (start_hint)
				*start_hint = curr_node;
			goto block_found;
		}
	}

	if (log_block)
		pmfs_error_mng(sb, "Unable to free log block %ld\n", blocknr);
	else
		pmfs_error_mng(sb, "Unable to free data block %ld\n", blocknr);
	dump_stack();

block_found:

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);
	free_steps += step;
}

inline void __pmfs_free_data_block(struct super_block *sb,
	unsigned long blocknr, unsigned short btype,
	struct pmfs_blocknode **start_hint)
{
	pmfs_dbg_verbose("Free data block %lu\n", blocknr);
	__pmfs_free_block(sb, blocknr, btype, start_hint, 0);
}

inline void __pmfs_free_log_block(struct super_block *sb,
	unsigned long blocknr, unsigned short btype,
	struct pmfs_blocknode **start_hint)
{
	pmfs_dbg_verbose("Free log block %lu\n", blocknr);
	__pmfs_free_block(sb, blocknr, btype, start_hint, 1);
}

void pmfs_free_meta_block(struct super_block *sb, unsigned long page_addr)
{
	timing_t free_time;

	PMFS_START_TIMING(free_meta_t, free_time);
	pmfs_dbg_verbose("Free meta block %lu\n", page_addr);
	pmfs_free_dram_page(page_addr);
	PMFS_END_TIMING(free_meta_t, free_time);
}

void pmfs_free_data_block(struct super_block *sb, unsigned long blocknr,
		      unsigned short btype)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	timing_t free_time;

	pmfs_dbg_verbose("Free data block %lu\n", blocknr);
	PMFS_START_TIMING(free_data_t, free_time);
	mutex_lock(&sbi->s_lock);
	__pmfs_free_block(sb, blocknr, btype, NULL, 0);
	mutex_unlock(&sbi->s_lock);
	PMFS_END_TIMING(free_data_t, free_time);
}

int pmfs_new_meta_blocks(struct super_block *sb, unsigned long *blocknr,
		unsigned int num, int zero)
{
	unsigned long page_addr;
	timing_t alloc_time;

	if (num != 1)
		return -EINVAL;

	PMFS_START_TIMING(new_meta_blocks_t, alloc_time);
	page_addr = pmfs_alloc_dram_page(sb, zero);
	if (page_addr == 0) {
		PMFS_END_TIMING(new_meta_blocks_t, alloc_time);
		return -EINVAL;
	}

	*blocknr = page_addr;
	PMFS_END_TIMING(new_meta_blocks_t, alloc_time);
	return 0;
}

/* Return how many blocks allocated */
int pmfs_new_data_blocks(struct super_block *sb, unsigned long *blocknr,
		unsigned int num, unsigned short btype, int zero)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i, *next_i;
	struct pmfs_blocknode *free_blocknode= NULL;
	void *bp;
	unsigned long num_blocks = 0;
	struct pmfs_blocknode *curr_node;
	int errval = 0;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;
	timing_t alloc_time;
	unsigned long step = 0;

	num_blocks = num * pmfs_get_numblocks(btype);
	if (num_blocks == 0)
		return -EINVAL;

	PMFS_START_TIMING(new_data_blocks_t, alloc_time);
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

//		new_block_low = (i->block_high + num_blocks) & ~(num_blocks - 1);
		new_block_low = i->block_high + 1;
		new_block_high = new_block_low + num_blocks - 1;

		if (new_block_high >= next_block_low) {
			/* Superpage allocation must succeed */
			if (btype > 0)
				continue;

			/* Otherwise, allocate the hole */
			if (next_i) {
				i->block_high = next_i->block_high;
				list_del(&next_i->link);
				free_blocknode = next_i;
				sbi->num_blocknode_allocated--;
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
				list_del(&next_i->link);
				free_blocknode = next_i;
				sbi->num_blocknode_allocated--;
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
				curr_node = pmfs_alloc_blocknode(sb);
				PMFS_ASSERT(curr_node);
				if (curr_node == NULL) {
					errval = -ENOSPC;
					break;
				}
				curr_node->block_low = new_block_low;
				curr_node->block_high = new_block_high;
				list_add(&curr_node->link, &i->link);
			}
			found = 1;
			break;
		}

		if ((new_block_low > (i->block_high + 1)) &&
			(new_block_high < (next_block_low - 1))) {
			/* Aligns somewhere in the middle */
			curr_node = pmfs_alloc_blocknode(sb);
			PMFS_ASSERT(curr_node);
			if (curr_node == NULL) {
				errval = -ENOSPC;
				break;
			}
			curr_node->block_low = new_block_low;
			curr_node->block_high = new_block_high;
			list_add(&curr_node->link, &i->link);
			found = 1;
			break;
		}
	}
	
	if (found == 1) {
		sbi->num_free_blocks -= num_blocks;
	}	

	mutex_unlock(&sbi->s_lock);

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);

	if (found == 0) {
		PMFS_END_TIMING(new_data_blocks_t, alloc_time);
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
//		memset_nt(bp, 0, size * num);
		memset_nt(bp, 0, PAGE_SIZE * num_blocks);
		pmfs_memlock_block(sb, bp);
	}
	*blocknr = new_block_low;

	pmfs_dbg_verbose("Alloc %u data blocks %lu\n", num, *blocknr);
	PMFS_END_TIMING(new_data_blocks_t, alloc_time);
	alloc_steps += step;
	return num_blocks / pmfs_get_numblocks(btype);
}

unsigned long pmfs_count_free_blocks(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	return sbi->num_free_blocks; 
}
