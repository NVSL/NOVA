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

static void pmfs_clear_datablock_inode(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
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
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_blocknode_lowhigh *p = NULL;
	struct pmfs_blocknode *blknode;
	unsigned long index;
	unsigned long blocknr;
	unsigned long i;
	unsigned long num_blocknode;
	u64 bp;

	num_blocknode = sbi->num_blocknode_allocated;
	sbi->num_blocknode_allocated = 0;
	for (i=0; i<num_blocknode; i++) {
		index = i & 0xFF;
		if (index == 0) {
			/* Find and get new data block */
			blocknr = i >> 8; /* 256 Entries in a block */
			bp = __pmfs_find_inode(sb, pi, blocknr);
			p = pmfs_get_block(sb, bp);
		}
		PMFS_ASSERT(p);
		blknode = pmfs_alloc_blocknode(sb);
		if (blknode == NULL)
                	PMFS_ASSERT(0);
		blknode->block_low = le64_to_cpu(p[index].block_low);
		blknode->block_high = le64_to_cpu(p[index].block_high);
		list_add_tail(&blknode->link, &sbi->block_inuse_head);
	}
}

static bool pmfs_can_skip_full_scan(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	__le64 root;
	unsigned int height, btype;
	unsigned long last_blocknr;

	if (!pi->root)
		return false;

	sbi->num_blocknode_allocated =
		le64_to_cpu(super->s_num_blocknode_allocated);
	sbi->num_free_blocks = le64_to_cpu(super->s_num_free_blocks);
	sbi->s_inodes_count = le32_to_cpu(super->s_inodes_count);
	sbi->s_free_inodes_count = le32_to_cpu(super->s_free_inodes_count);
	sbi->s_inodes_used_count = le32_to_cpu(super->s_inodes_used_count);
	sbi->s_free_inode_hint = le32_to_cpu(super->s_free_inode_hint);
	sbi->s_max_inode = le32_to_cpu(super->s_max_inode);

	pmfs_init_blockmap_from_inode(sb);

	root = pi->root;
	height = pi->height;
	btype = pi->i_blk_type;
	/* pi->i_size can not be zero */
	last_blocknr = (le64_to_cpu(pi->i_size) - 1) >>
					pmfs_inode_blk_shift(pi);

	/* Clearing the datablock inode */
	pmfs_clear_datablock_inode(sb);

	pmfs_free_inode_subtree(sb, root, height, btype,
						last_blocknr);

	return true;
}


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
	struct pmfs_inode *pi =  pmfs_get_inode(sb, PMFS_BLOCKNODE_IN0);
	struct pmfs_blocknode_lowhigh *p;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i;
	struct pmfs_super_block *super;
	pmfs_transaction_t *trans;
	u64 bp;
	int j, k;
	int errval;
	
	num_blocks = ((sbi->num_blocknode_allocated * sizeof(struct 
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

		if (j == 256) {
			j = 0;
			/* Lock the data block */
			pmfs_memlock_block(sb, p);
			pmfs_flush_buffer(p, 4096, false);
		}
		
		k++;
	}
	
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
	super->s_num_blocknode_allocated = 
			cpu_to_le64(sbi->num_blocknode_allocated);
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

	if (free_blocknode)
		pmfs_free_blocknode(sb, free_blocknode);

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
}

static int alloc_bm(struct scan_bitmap *bm, unsigned long initsize)
{
	bm->bitmap_4k_size = (initsize >> (PAGE_SHIFT + 0x3)) + 1;
	bm->bitmap_2M_size = (initsize >> (PAGE_SHIFT_2M + 0x3)) + 1;
	bm->bitmap_1G_size = (initsize >> (PAGE_SHIFT_1G + 0x3)) + 1;

	/* Alloc memory to hold the block alloc bitmap */
	bm->bitmap_4k = kzalloc(bm->bitmap_4k_size, GFP_KERNEL);
	bm->bitmap_2M = kzalloc(bm->bitmap_2M_size, GFP_KERNEL);
	bm->bitmap_1G = kzalloc(bm->bitmap_1G_size, GFP_KERNEL);

	if (!bm->bitmap_4k || !bm->bitmap_2M || !bm->bitmap_1G) {
		free_bm(bm);
		return -ENOMEM;
	}

	return 0;
}

int pmfs_setup_blocknode_map(struct super_block *sb)
{
	struct pmfs_super_block *super = pmfs_get_super(sb);
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	pmfs_journal_t *journal = pmfs_get_journal(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct scan_bitmap bm;
	unsigned long initsize = le64_to_cpu(super->s_size);
	bool value = false;
	int ret;

	mutex_init(&sbi->inode_table_mutex);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);
	
	value = pmfs_can_skip_full_scan(sb);
	if (value) {
		pmfs_dbg_verbose("PMFS: Skipping full scan of inodes...\n");
		return 0;
	}

	ret = alloc_bm(&bm, initsize);
	if (ret)
		return ret;

	/* Clearing the datablock inode */
	pmfs_clear_datablock_inode(sb);

	pmfs_inode_table_crawl_recursive(sb, &bm, le64_to_cpu(pi->root),
						pi->height, pi->i_blk_type);

	/* Reserving tow inodes - Inode 0 and Inode for datablock */
	sbi->s_free_inodes_count = sbi->s_inodes_count -  
		(sbi->s_inodes_used_count + 2);
	
	/* set the block 0 as this is used */
	sbi->s_free_inode_hint = PMFS_FREE_INODE_HINT_START;

	/* initialize the num_free_blocks to */
	sbi->num_free_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);
	pmfs_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);

	pmfs_build_blocknode_map(sb, &bm);

	free_bm(&bm);

	return 0;
}


/************************** CoolFS recovery ****************************/

struct scan_bitmap recovery_bm;

static int pmfs_recover_inode(struct super_block *sb, struct pmfs_inode *pi,
	struct scan_bitmap *bm, int cpuid)
{
	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		pmfs_dbg("This is thread %d, processing file %p, "
				"head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pi->log_head, pi->log_tail);
		break;
	case S_IFDIR:
		pmfs_dbg("This is thread %d, processing dir %p, "
				"head 0x%llx, tail 0x%llx\n",
				cpuid, pi, pi->log_head, pi->log_tail);
		break;
	case S_IFLNK:
		break;
	default:
		break;
	}

//	udelay(10);
	return 0;
}

/*********************** Singlethread recovery *************************/

int *processed;

static void pmfs_inode_table_singlethread_crawl(struct super_block *sb,
	struct scan_bitmap *bm, unsigned long block,
	u32 height, unsigned long start_ino, u32 btype)
{
	__le64 *node;
	unsigned int i;
	struct pmfs_inode *pi;
//	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned int meta_bits = blk_type_to_shift[btype] - PMFS_INODE_BITS;
	unsigned int node_bits;
	unsigned long ino_off;
//	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	node = pmfs_get_block(sb, block);
	if (height == 0)
		node_bits = 0;
	else
		node_bits = meta_bits + (height - 1) * META_BLK_SHIFT;

	if (height == 0) {
		unsigned int inodes_per_block = INODES_PER_BLOCK(btype);
//		if (likely(btype == PMFS_BLOCK_TYPE_2M))
//			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
//		else
//			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

//		sbi->s_inodes_count += inodes_per_block;
		for (i = 0; i < inodes_per_block; i++) {
			pi = (struct pmfs_inode *)((void *)node +
                                                        PMFS_INODE_SIZE * i);
			if (le16_to_cpu(pi->i_links_count) == 0 &&
				(le16_to_cpu(pi->i_mode) == 0 ||
				le32_to_cpu(pi->i_dtime))) {
					/* Empty inode */
					continue;
			}
//			sbi->s_inodes_used_count++;
//			pmfs_inode_crawl(sb, bm, pi);
			pmfs_dbg("ino: %lu\n", start_ino + i);
			pmfs_recover_inode(sb, pi, bm, smp_processor_id());
			processed[smp_processor_id()]++;
		}
		return;
	}

//	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		ino_off = start_ino + (i << node_bits);
		pmfs_inode_table_singlethread_crawl(sb, NULL,
			le64_to_cpu(node[i]), height - 1, ino_off, btype);
	}
}

int pmfs_singlethread_recovery(struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	pmfs_journal_t *journal = pmfs_get_journal(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long initsize = le64_to_cpu(super->s_size);
	bool value = false;
	int cpus = num_online_cpus();
	int i;
	int ret = 0;

	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);

	processed = kzalloc(cpus * sizeof(int), GFP_KERNEL);
	if (!processed)
		return -ENOMEM;

	value = pmfs_can_skip_full_scan(sb);
	if (value) {
		pmfs_dbg_verbose("PMFS: Skipping full scan of inodes...\n");
		ret = 0;
		goto out;
	}

	ret = alloc_bm(&recovery_bm, initsize);
	if (ret)
		goto out;

	/* Clearing the datablock inode */
	pmfs_clear_datablock_inode(sb);

	pmfs_dbg("%s\n", __func__);
	pmfs_inode_table_singlethread_crawl(sb, NULL,
			le64_to_cpu(pi->root), pi->height, 0, pi->i_blk_type);

	for (i = 0; i < cpus; i++)
		pmfs_dbg("CPU %d: recovered %d\n", i, processed[i]);

	/* Reserving tow inodes - Inode 0 and Inode for datablock */
	sbi->s_free_inodes_count = sbi->s_inodes_count -
			(sbi->s_inodes_used_count + 2);

	/* set the block 0 as this is used */
	sbi->s_free_inode_hint = PMFS_FREE_INODE_HINT_START;

	/* initialize the num_free_blocks to */
	sbi->num_free_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);
	pmfs_init_blockmap(sb, le64_to_cpu(journal->base) + sbi->jsize);

	pmfs_build_blocknode_map(sb, &recovery_bm);

	free_bm(&recovery_bm);
out:
	kfree(processed);
	return ret;
}

/*********************** Multithread recovery *************************/

struct task_ring {
	struct pmfs_inode *tasks[512];
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

static inline void task_ring_enqueue(struct task_ring *ring,
	struct pmfs_inode *pi)
{
	pmfs_dbg_verbose("Enqueue at %d\n", ring->enqueue);
	ring->tasks[ring->enqueue] = pi;
	ring->enqueue = (ring->enqueue + 1) % 512;
}

static inline struct pmfs_inode *task_ring_dequeue(struct task_ring *ring)
{
	struct pmfs_inode *pi = ring->tasks[ring->dequeue];

	if (!pi)
		BUG();

	ring->tasks[ring->dequeue] = 0;
	ring->dequeue = (ring->dequeue + 1) % 512;
	ring->processed++;

	return pi;
}

static struct task_struct **threads;
static struct task_ring *task_rings;
wait_queue_head_t finish_wq;

static int thread_func(void *data)
{
	struct super_block *sb = data;
	struct pmfs_inode *pi;
	int cpuid = smp_processor_id();
	struct task_ring *ring = &task_rings[cpuid];

	while (!kthread_should_stop()) {
		while(!task_ring_is_empty(ring)) {
			pi = task_ring_dequeue(ring);
			pmfs_recover_inode(sb, pi, &recovery_bm, cpuid);
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
	struct scan_bitmap *bm, int cpus, unsigned long block,
	u32 height, unsigned long start_ino, u32 btype)
{
	__le64 *node;
	unsigned int i;
	unsigned long ino_off;
	struct task_ring *ring = NULL;
	struct pmfs_inode *pi;
	unsigned int meta_bits = blk_type_to_shift[btype] - PMFS_INODE_BITS;
	unsigned int node_bits;
//	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	node = pmfs_get_block(sb, block);
	if (height == 0)
		node_bits = 0;
	else
		node_bits = meta_bits + (height - 1) * META_BLK_SHIFT;

	if (height == 0) {
		unsigned int inodes_per_block = INODES_PER_BLOCK(btype);
//		if (likely(btype == PMFS_BLOCK_TYPE_2M))
//			set_bit(block >> PAGE_SHIFT_2M, bm->bitmap_2M);
//		else
//			set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);

//		sbi->s_inodes_count += inodes_per_block;
		for (i = 0; i < inodes_per_block; i++) {
			pi = (struct pmfs_inode *)((void *)node +
                                                        PMFS_INODE_SIZE * i);
			if (le16_to_cpu(pi->i_links_count) == 0 &&
				(le16_to_cpu(pi->i_mode) == 0 ||
				le32_to_cpu(pi->i_dtime))) {
					/* Empty inode */
					continue;
			}
//			sbi->s_inodes_used_count++;
//			pmfs_inode_crawl(sb, bm, pi);

			while ((ring = get_free_ring(cpus, ring)) == NULL) {
				wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
			}

			pmfs_dbg_verbose("Get ring %p, pi %p\n", ring, pi);
			task_ring_enqueue(ring, pi);
			wake_up_interruptible(&ring->assign_wq);
		}
		return;
	}

//	set_bit(block >> PAGE_SHIFT, bm->bitmap_4k);
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		ino_off = start_ino + (i << node_bits);
		pmfs_inode_table_multithread_crawl(sb, NULL, cpus,
			le64_to_cpu(node[i]), height - 1, ino_off, btype);
	}
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
		pmfs_dbg("Ring %d recovered %d\n", i, ring->processed);
		total += ring->processed;
	}

	pmfs_dbg("Total recovered %d\n", total);
}

void pmfs_mutithread_recovery(struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	int cpus;
	int ret;

	cpus = num_online_cpus();
	pmfs_dbg("%s: %d cpus\n", __func__, cpus);

	ret = allocate_resources(sb, cpus);
	if (ret)
		return;

	pmfs_inode_table_multithread_crawl(sb, NULL, cpus,
			le64_to_cpu(pi->root), pi->height, 0, pi->i_blk_type);

	wait_to_finish(cpus);
	free_resources();
	return;
}
