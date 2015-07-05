/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
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
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "pmfs.h"
#include "xip.h"

unsigned int blk_type_to_shift[PMFS_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[PMFS_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

struct kmem_cache *pmfs_mempair_cachep;

static inline struct mem_addr *pmfs_alloc_mempair(struct super_block *sb)
{
	struct mem_addr *p;
	p = (struct mem_addr *)
		kmem_cache_alloc(pmfs_mempair_cachep, GFP_NOFS);
	p->page = NULL;
	p->nvmm_entry = p->nvmm = p->dram = 0;
	atomic64_inc(&mempair_alloc);
	return p;
}

static inline void pmfs_free_mempair(struct super_block *sb,
	struct mem_addr *pair)
{
	kmem_cache_free(pmfs_mempair_cachep, pair);
	atomic64_inc(&mempair_free);
}

void pmfs_print_inode_entry(struct pmfs_file_write_entry *entry)
{
	pmfs_dbg("entry @%p: pgoff %u, num_pages %u, block 0x%llx, "
		"size %llu\n", entry, entry->pgoff, entry->num_pages,
		entry->block, entry->size);
}

/*
 * find the offset to the block represented by the given inode's file
 * relative block number.
 */
u64 pmfs_find_nvmm_block(struct inode *inode, unsigned long file_blocknr)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	u32 blk_shift;
	unsigned long blk_offset, blocknr = file_blocknr;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	u64 bp;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - sb->s_blocksize_bits;
	blk_offset = file_blocknr & ((1 << blk_shift) - 1);
	blocknr = file_blocknr >> blk_shift;

	if (blocknr >= (1UL << (sih->height * meta_bits)))
		return 0;

	pmfs_dbg_verbose("%s: inode %lu, si %p, root 0x%llx, height %u\n",
		__func__, inode->i_ino, si, sih->root, sih->height);
	bp = __pmfs_find_nvmm_block(sb, si, NULL, blocknr);
	pmfs_dbg1("find_nvmm_block %lx, %x %llx blk_p %p blk_shift %x"
		" blk_offset %lx\n", file_blocknr, sih->height, bp,
		pmfs_get_block(sb, bp), blk_shift, blk_offset);

	if (bp == 0)
		return 0;
	return bp + (blk_offset << sb->s_blocksize_bits);
}

/*
 * find the mem addr pair represented by the given inode's file
 * relative block number.
 */
struct mem_addr *pmfs_get_mem_pair(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_inode_info *si,
	unsigned long file_blocknr)
{
	struct pmfs_inode_info_header *sih = si->header;
	u32 blk_shift;
	unsigned long blk_offset, blocknr = file_blocknr;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;

	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - sb->s_blocksize_bits;
	blk_offset = file_blocknr & ((1 << blk_shift) - 1);
	blocknr = file_blocknr >> blk_shift;

	if (blocknr >= (1UL << (sih->height * meta_bits)))
		return NULL;

	pmfs_dbg_verbose("%s: si %p, root 0x%llx, height %u\n",
		__func__, si, sih->root, sih->height);
	return __pmfs_get_mem_pair(sb, si, blocknr);
}

/* recursive_find_region: recursively search the btree to find hole or data
 * in the specified range
 * Input:
 * block: points to the root of the b-tree
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
static int recursive_find_region(struct super_block *sb, __le64 block,
	u32 height, unsigned long first_blocknr, unsigned long last_blocknr,
	int *data_found, int *hole_found, int hole)
{
	unsigned int meta_bits = META_BLK_SHIFT;
	__le64 *node;
	unsigned long first_blk, last_blk, node_bits, blocks = 0;
	unsigned int first_index, last_index, i;

	node_bits = (height - 1) * meta_bits;

	first_index = first_blocknr >> node_bits;
	last_index = last_blocknr >> node_bits;

	node = pmfs_get_block(sb, le64_to_cpu(block));

	for (i = first_index; i <= last_index; i++) {
		if (height == 1 || node[i] == 0) {
			if (node[i]) {
				*data_found = 1;
				if (!hole)
					goto done;
			} else {
				*hole_found = 1;
			}

			if (!*hole_found || !hole)
				blocks += (1UL << node_bits);
		} else {
			first_blk = (i == first_index) ?  (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			blocks += recursive_find_region(sb, node[i], height - 1,
				first_blk, last_blk, data_found, hole_found,
				hole);
			if (!hole && *data_found)
				goto done;
			/* cond_resched(); */
		}
	}
done:
	return blocks;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long pmfs_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	unsigned long blocks = 0, offset_in_block;
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !sih->root) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & ((1UL << data_bits) - 1);

	if (sih->height == 0) {
		data_found = 1;
		goto out;
	}

	first_blocknr = *offset >> data_bits;
	last_blocknr = inode->i_size >> data_bits;

	pmfs_dbg_verbose("find_region offset %llx, first_blocknr %lx,"
		" last_blocknr %lx hole %d\n",
		  *offset, first_blocknr, last_blocknr, hole);

	blocks = recursive_find_region(inode->i_sb, sih->root, sih->height,
		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

out:
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

/* examine the meta-data block node up to the end_idx for any non-null
 * pointers. if found return false, else return true.
 * required to determine if a meta-data block contains no pointers and hence
 * can be freed.
 */
static inline bool is_empty_meta_block(__le64 *node, unsigned int start_idx,
	unsigned int end_idx)
{
	int i, last_idx = (1 << META_BLK_SHIFT) - 1;
	for (i = 0; i < start_idx; i++)
		if (unlikely(node[i]))
			return false;
	for (i = end_idx + 1; i <= last_idx; i++)
		if (unlikely(node[i]))
			return false;
	return true;
}

/* recursive_truncate_file_blocks: recursively deallocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * end: last byte offset of the range
 */
static int recursive_truncate_file_blocks(struct super_block *sb, __le64 block,
	u32 height, u32 btype, unsigned long first_blocknr,
	unsigned long last_blocknr, unsigned long start_pgoff,
	bool *meta_empty)
{
	unsigned long first_blk, last_blk, page_addr;
	unsigned int node_bits, first_index, last_index, i;
	__le64 *node;
	unsigned int freed = 0, bzero;
	int start, end;
	bool mpty, all_range_freed = true;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long pgoff;
	struct pmfs_file_write_entry *entry;
	struct mem_addr *pair;
	unsigned long start_blocknr = 0, num_free = 0;

	node = (__le64 *)block;

	node_bits = (height - 1) * META_BLK_SHIFT;

	start = first_index = first_blocknr >> node_bits;
	end = last_index = last_blocknr >> node_bits;

	if (height == 1) {
		struct pmfs_blocknode *start_hint = NULL;
		mutex_lock(&sbi->s_lock);
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			/* Freeing the data block */
			pair = (struct mem_addr *)node[i];
			pgoff = start_pgoff + i;

			if (pair->page || pair->dram) {
				pmfs_free_cache_block(pair);
			}
			if (pair->nvmm_entry) {
				entry = pmfs_get_block(sb, pair->nvmm_entry);
				entry->invalid_pages++;

				if (start_blocknr == 0) {
					start_blocknr = pair->nvmm;
					num_free = 1;
				} else {
					if (pair->nvmm == start_blocknr + num_free) {
						num_free++;
					} else {
						/* A new start */
						pmfs_free_data_blocks(sb, start_blocknr,
							num_free, btype, &start_hint, 0);
						start_blocknr = pair->nvmm;
						num_free = 1;
					}
				}
				pair->nvmm_entry = 0;
				pair->nvmm = 0;
			}

			pmfs_free_mempair(sb, pair);
			node[i] = 0;
			freed++;
		}
		if (start_blocknr)
			pmfs_free_data_blocks(sb, start_blocknr,
				num_free, btype, &start_hint, 0);
		mutex_unlock(&sbi->s_lock);
	} else {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			pgoff = start_pgoff + (i << node_bits);
			freed += recursive_truncate_file_blocks(sb,
				DRAM_ADDR(node[i]), height - 1, btype,
				first_blk, last_blk, pgoff, &mpty);
			/* cond_resched(); */
			if (mpty) {
				/* Freeing the meta-data block */
				page_addr = node[i];
				pmfs_free_meta_block(sb, page_addr);
			} else {
				if (i == first_index)
				    start++;
				else if (i == last_index)
				    end--;
				all_range_freed = false;
			}
		}
	}
	if (all_range_freed) {
		*meta_empty = true;
	} else {
		/* Zero-out the freed range if the meta-block in not empty */
		if (start <= end) {
			bzero = (end - start + 1) * sizeof(u64);
			memset(&node[start], 0, bzero);
		}
		*meta_empty = false;
	}
	return freed;
}

/* recursive_truncate_meta_blocks: recursively deallocate meta blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * end: last byte offset of the range
 */
static int recursive_truncate_meta_blocks(struct super_block *sb, __le64 block,
	u32 height, unsigned long first_blocknr, unsigned long last_blocknr,
	unsigned long start_pgoff, bool *meta_empty)
{
	unsigned long first_blk, last_blk, page_addr;
	unsigned int node_bits, first_index, last_index, i;
	__le64 *node;
	unsigned int freed = 0, bzero;
	int start, end;
	bool mpty, all_range_freed = true;
	unsigned long pgoff;
	struct mem_addr *pair;

	node = (__le64 *)block;

	node_bits = (height - 1) * META_BLK_SHIFT;

	start = first_index = first_blocknr >> node_bits;
	end = last_index = last_blocknr >> node_bits;

	if (height == 1) {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			/* Freeing the page cache block */
			pair = (struct mem_addr *)node[i];
			if (pair->page || pair->dram) {
				pmfs_free_cache_block(pair);
				freed++;
			}
			pmfs_free_mempair(sb, pair);
		}
		*meta_empty = true;
		return freed;
	} else {
		for (i = first_index; i <= last_index; i++) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			pgoff = start_pgoff + (i << node_bits);
			freed += recursive_truncate_meta_blocks(sb,
				DRAM_ADDR(node[i]), height - 1,
				first_blk, last_blk, pgoff, &mpty);
			/* cond_resched(); */
			if (mpty) {
				/* Freeing the meta-data block */
				page_addr = node[i];
				freed++;
				pmfs_free_meta_block(sb, page_addr);
			} else {
				if (i == first_index)
				    start++;
				else if (i == last_index)
				    end--;
				all_range_freed = false;
			}
		}
	}
	if (all_range_freed) {
		*meta_empty = true;
	} else {
		/* Zero-out the freed range if the meta-block in not empty */
		if (start <= end) {
			bzero = (end - start + 1) * sizeof(u64);
			pmfs_memunlock_block(sb, node);
			memset(&node[start], 0, bzero);
			pmfs_memlock_block(sb, node);
		}
		*meta_empty = false;
	}
	return freed;
}

void pmfs_free_mem_addr(struct super_block *sb, __le64 addr, u32 btype)
{
	struct mem_addr *pair = (struct mem_addr *)addr;
	struct pmfs_file_write_entry *entry;

	if (!pair)
		return;

	if (pair->nvmm_entry) {
		entry = (struct pmfs_file_write_entry *)
				pmfs_get_block(sb, pair->nvmm_entry);
		entry->invalid_pages++;
		pmfs_free_data_blocks(sb, pair->nvmm, 1, btype, NULL, 1);
		pair->nvmm_entry = 0;
		pair->nvmm = 0;
	}

	if (pair->page || pair->dram) {
		pmfs_free_cache_block(pair);
	}

	pmfs_free_mempair(sb, pair);
}

unsigned int pmfs_free_file_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr)
{
	unsigned long first_blocknr;
	unsigned int freed;
	bool mpty;
	timing_t delete_time;

	PMFS_START_TIMING(delete_file_tree_t, delete_time);
	if (!root) {
		PMFS_END_TIMING(delete_file_tree_t, delete_time);
		return 0;
	}

	if (height == 0) {
		pmfs_free_mem_addr(sb, root, btype);
		freed = 1;
	} else {
		first_blocknr = 0;

		freed = recursive_truncate_file_blocks(sb, DRAM_ADDR(root),
			height, btype, first_blocknr, last_blocknr, 0, &mpty);
		BUG_ON(!mpty);
		first_blocknr = root;
		pmfs_free_meta_block(sb, first_blocknr);
	}
	PMFS_END_TIMING(delete_file_tree_t, delete_time);
	return freed;
}

unsigned int pmfs_free_file_meta_blocks(struct super_block *sb,
	struct pmfs_inode_info_header *sih, unsigned long last_blocknr)
{
	unsigned long first_blocknr;
	unsigned int freed = 0;
	bool mpty;
	__le64 root = sih->root;
	u32 height = sih->height;

	if (!root)
		return 0;

	if (height == 0) {
		struct mem_addr *pair = (struct mem_addr *)root;
		if (pair->page || pair->dram) {
			pmfs_free_cache_block(pair);
			freed = 1;
		}
		pmfs_free_mempair(sb, pair);
		sih->root = 0;
		return freed;
	}

	first_blocknr = 0;

	freed = recursive_truncate_meta_blocks(sb, DRAM_ADDR(root),
			height, first_blocknr, last_blocknr, 0, &mpty);
	BUG_ON(!mpty);
	first_blocknr = root;
	pmfs_free_meta_block(sb, first_blocknr);
	freed++;
	sih->root = 0;

	return freed;
}

static void pmfs_decrease_file_btree_height(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_inode_info *si,
	unsigned long newsize, __le64 newroot)
{
	struct pmfs_inode_info_header *sih = si->header;
	unsigned int height = sih->height, new_height = 0;
	unsigned long last_blocknr, page_addr;
	__le64 *root;

	if (pi->i_blocks == 0 || newsize == 0) {
		/* root must be NULL */
		BUG_ON(newroot != 0);
		goto update_root_and_height;
	}

	last_blocknr = ((newsize + pmfs_inode_blk_size(pi) - 1) >>
		pmfs_inode_blk_shift(pi)) - 1;
	while (last_blocknr > 0) {
		last_blocknr = last_blocknr >> META_BLK_SHIFT;
		new_height++;
	}
	if (height == new_height)
		return;
	pmfs_dbg_verbose("reducing tree height %x->%x\n", height, new_height);
	while (height > new_height) {
		/* freeing the meta block */
		root = (__le64 *)DRAM_ADDR(newroot);
		page_addr = newroot;
		newroot = root[0];
		pmfs_free_meta_block(sb, page_addr);
		height--;
	}
update_root_and_height:
	sih->root = newroot;
	sih->height = new_height;
}

static unsigned long pmfs_inode_count_iblocks_recursive(struct super_block *sb,
		__le64 block, u32 height)
{
	__le64 *node;
	unsigned int i;
	unsigned long i_blocks = 0;

	if (height == 0)
		return 1;
	node = pmfs_get_block(sb, le64_to_cpu(block));
	for (i = 0; i < (1 << META_BLK_SHIFT); i++) {
		if (node[i] == 0)
			continue;
		i_blocks += pmfs_inode_count_iblocks_recursive(sb, node[i],
								height - 1);
	}
	return i_blocks;
}

static inline
unsigned long pmfs_inode_file_count_iblocks (struct super_block *sb,
	struct pmfs_inode *pi, struct inode *inode)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	unsigned long iblocks = 0;

	iblocks = pmfs_inode_count_iblocks_recursive(sb, sih->root,
							sih->height);
	iblocks += sih->log_pages;
	return (iblocks << (pmfs_inode_blk_shift(pi) - sb->s_blocksize_bits));
}

/* Support for sparse files: even though pi->i_size may indicate a certain
 * last_blocknr, it may not be true for sparse files. Specifically, last_blocknr
 * can not be more than the maximum allowed by the inode's tree height.
 */
static inline unsigned long pmfs_sparse_last_blocknr(unsigned int height,
		unsigned long last_blocknr)
{
	if (last_blocknr >= (1UL << (height * META_BLK_SHIFT)))
		last_blocknr = (1UL << (height * META_BLK_SHIFT)) - 1;
	return last_blocknr;
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void __pmfs_truncate_file_blocks(struct inode *inode, loff_t start,
				    loff_t end)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	unsigned long first_blocknr, last_blocknr;
	__le64 root;
	unsigned int freed = 0;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int meta_bits = META_BLK_SHIFT;
	bool mpty;

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;

	if (!sih->root)
		return;

	pmfs_dbg_verbose("truncate: pi %p iblocks %llx %llx %llx %x %llx\n", pi,
			 pi->i_blocks, start, end, sih->height, pi->i_size);

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (pi->i_flags & cpu_to_le32(PMFS_EOFBLOCKS_FL)) {
		last_blocknr = (1UL << (sih->height * meta_bits)) - 1;
	} else {
		if (end == 0)
			return;
		last_blocknr = (end - 1) >> data_bits;
		last_blocknr = pmfs_sparse_last_blocknr(sih->height,
			last_blocknr);
	}

	if (first_blocknr > last_blocknr)
		return;

	root = sih->root;

	if (sih->height == 0) {
		pmfs_free_mem_addr(sb, root, pi->i_blk_type);
		freed = 1;
		root = 0;
	} else {
		freed = recursive_truncate_file_blocks(sb, DRAM_ADDR(root),
			sih->height, pi->i_blk_type, first_blocknr,
			last_blocknr, 0, &mpty);
		if (mpty) {
			first_blocknr = root;
			pmfs_free_meta_block(sb, first_blocknr);
			root = 0;
		}
	}
	/* if we are called during mount, a power/system failure had happened.
	 * Don't trust inode->i_blocks; recalculate it by rescanning the inode
	 */
	if (pmfs_is_mounting(sb))
		inode->i_blocks = pmfs_inode_file_count_iblocks(sb, pi, inode);
	else
		inode->i_blocks -= (freed * (1 << (data_bits -
				sb->s_blocksize_bits)));

	pmfs_memunlock_inode(sb, pi);
	pi->i_blocks = cpu_to_le64(inode->i_blocks);
	pmfs_decrease_file_btree_height(sb, pi, si, start, root);
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(sb, pi, inode->i_size);
	pmfs_memlock_inode(sb, pi);

	return;
}

static int pmfs_increase_file_btree_height(struct super_block *sb,
	struct pmfs_inode_info_header *sih, u32 new_height)
{
	u32 height = sih->height;
	__le64 *root, prev_root = sih->root;
	unsigned long page_addr;
	int errval = 0;

	pmfs_dbg_verbose("increasing tree height %x:%x, prev root 0x%llx\n",
						height, new_height, prev_root);
	while (height < new_height) {
		/* allocate the meta block */
		errval = pmfs_new_meta_block(sb, &page_addr, 1, 0);
		if (errval) {
			pmfs_err(sb, "failed to increase btree height\n");
			break;
		}
		root = (__le64 *)DRAM_ADDR(page_addr);
		root[0] = prev_root;
		prev_root = page_addr;
		height++;
	}
	sih->root = prev_root;
	sih->height = height;
	pmfs_dbg_verbose("increased tree height, new root 0x%llx\n",
							prev_root);
	return errval;
}

static void assign_nvmm(struct pmfs_inode *pi,
	struct pmfs_file_write_entry *data, struct mem_addr *leaf,
	struct scan_bitmap *bm, unsigned long pgoff)
{
	if (data->pgoff > pgoff || data->pgoff +
			data->num_pages <= pgoff) {
		pmfs_dbg("Entry ERROR: pgoff %lu, entry pgoff %u, "
			"num %u\n", pgoff, data->pgoff, data->num_pages);
		BUG();
	}

	leaf->nvmm = (data->block >> PAGE_SHIFT) + pgoff - data->pgoff;
	if (bm) {
		pmfs_dbgv("%s: inode %llu set %lu\n", __func__,
				pi->pmfs_ino << PMFS_INODE_BITS, leaf->nvmm);
		set_bm(leaf->nvmm, bm, BM_4K);
	}
}

static int recursive_assign_blocks(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_file_write_entry *data,
	struct scan_bitmap *bm, __le64 block, u32 height,
	unsigned long first_blocknr, unsigned long last_blocknr,
	u64 address, unsigned long start_pgoff, bool nvmm,
	bool free, bool alloc_dram)
{
	int i, errval;
	unsigned int meta_bits = META_BLK_SHIFT, node_bits;
	__le64 *node;
	unsigned long blocknr, first_blk, last_blk;
	unsigned long pgoff;
	unsigned int first_index, last_index;
	struct pmfs_file_write_entry *entry;
	struct mem_addr *leaf;
//	unsigned int flush_bytes;
//	struct pmfs_blocknode *hint = NULL;

	node = (__le64 *)block;

	node_bits = (height - 1) * meta_bits;

	first_index = first_blocknr >> node_bits;
	last_index = last_blocknr >> node_bits;

	pmfs_dbg_verbose("%s: node 0x%llx, height %u\n",
				__func__, block, height);

	for (i = first_index; i <= last_index; i++) {
		if (height == 1) {
			if (node[i] == 0) {
				node[i] = (unsigned long)pmfs_alloc_mempair(sb);
				if (node[i] == 0) {
					pmfs_dbg("%s: alloc failed\n",
						__func__);
					return -EINVAL;
				}
				leaf = (struct mem_addr *)node[i];
				leaf->nvmm_entry = leaf->nvmm = leaf->dram = 0;
			}
			pmfs_dbg_verbose("node[%d] @ 0x%llx\n", i, node[i]);
			leaf = (struct mem_addr *)node[i];
			pgoff = start_pgoff + i;
			if (leaf->nvmm_entry && nvmm) {
				entry = pmfs_get_block(sb, leaf->nvmm_entry);
				entry->invalid_pages++;
				if (bm)
					clear_bm(leaf->nvmm, bm, BM_4K);
				if (free)
					pmfs_free_data_blocks(sb, leaf->nvmm,
						1, pi->i_blk_type, NULL, 1);
				pmfs_dbg_verbose("Free block @ %lu\n",
							leaf->nvmm);
				//FIXME: garbage collection
				pi->i_blocks--;
			}
			if (alloc_dram) {
				if (!leaf->page && leaf->dram == 0) {
					errval = pmfs_new_cache_block(sb, leaf,
									0, 0);
					if (errval)
						goto fail;
					leaf->dram |= UNINIT_BIT;
					if (leaf->nvmm_entry)
						/* Outdate with NVMM */
						leaf->dram |= OUTDATE_BIT;
				}
			} else {
				if (nvmm) {
					leaf->nvmm_entry = address;
					assign_nvmm(pi, data, leaf, bm, pgoff);
				} else {
					leaf->dram = address;
				}
			}
			pmfs_dbg_verbose("Assign block %d to %llu\n", i, 
							address);
		} else {
			if (node[i] == 0) {
				/* allocate the meta block */
				errval = pmfs_new_meta_block(sb,
							&blocknr, 1, 0);
				if (errval) {
					pmfs_dbg("alloc meta blk failed\n");
					goto fail;
				}
				node[i] = blocknr;
			}

			first_blk = (i == first_index) ? (first_blocknr &
				((1 << node_bits) - 1)) : 0;

			last_blk = (i == last_index) ? (last_blocknr &
				((1 << node_bits) - 1)) : (1 << node_bits) - 1;

			pgoff = start_pgoff + (i << node_bits);
			errval = recursive_assign_blocks(sb, pi, data, bm,
				DRAM_ADDR(node[i]), height - 1, first_blk,
				last_blk, address, pgoff, nvmm,
				free, alloc_dram);
			if (errval < 0)
				goto fail;
		}
	}
	errval = 0;
fail:
	return errval;
}

static int __pmfs_assign_blocks(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_info_header *sih, struct pmfs_file_write_entry *data,
	struct scan_bitmap *bm,	u64 address, bool nvmm, bool free,
	bool alloc_dram)
{
	unsigned long max_blocks;
	unsigned int height;
	unsigned int data_bits = blk_type_to_shift[pi->i_blk_type];
	unsigned int blk_shift, meta_bits = META_BLK_SHIFT;
	unsigned long first_blocknr, last_blocknr, total_blocks;
	unsigned int file_blocknr = data->pgoff;
	unsigned int num = data->num_pages;
	int errval;
	/* convert the 4K blocks into the actual blocks the inode is using */
	blk_shift = data_bits - sb->s_blocksize_bits;

	first_blocknr = file_blocknr >> blk_shift;
	last_blocknr = (file_blocknr + num - 1) >> blk_shift;

	pmfs_dbg_verbose("assign_blocks height %d file_blocknr %u "
			"address 0x%llx, num %u, root %llu, "
			"first blocknr 0x%lx, last_blocknr 0x%lx\n",
			sih->height, file_blocknr, address, num,
			sih->root, first_blocknr, last_blocknr);

	height = sih->height;

	blk_shift = height * meta_bits;

	max_blocks = 0x1UL << blk_shift;

	if (last_blocknr > max_blocks - 1) {
		/* B-tree height increases as a result of this allocation */
		total_blocks = last_blocknr >> blk_shift;
		while (total_blocks > 0) {
			total_blocks = total_blocks >> meta_bits;
			height++;
		}
		if (height > 3) {
			pmfs_dbg("[%s:%d] Max file size. Cant grow the file\n",
				__func__, __LINE__);
			errval = -ENOSPC;
			goto fail;
		}
	}

	if (!sih->root) {
		if (height == 0) {
			struct mem_addr *root;
			root = pmfs_alloc_mempair(sb);
			if (!root) {
				pmfs_dbg("%s: root allocation failed\n",
					__func__);
				return -EINVAL;
			}

			root->dram = root->nvmm = root->nvmm_entry = 0;
			root->page = NULL;
			if (alloc_dram) {
				errval = pmfs_new_cache_block(sb, root, 0, 0);
				if (errval)
					goto fail;
				root->dram |= UNINIT_BIT;
			} else {
				if (nvmm) {
					root->nvmm_entry = address;
					assign_nvmm(pi, data, root, bm, 0);
				} else {
					root->dram = address;
				}
			}

			pmfs_dbg_verbose("Set root @%p\n", root);
			sih->root = cpu_to_le64(root);
			sih->height = height;
		} else {
			errval = pmfs_increase_file_btree_height(sb, sih,
								height);
			if (errval) {
				pmfs_dbg("[%s:%d] failed: inc btree"
					" height\n", __func__, __LINE__);
				goto fail;
			}
			errval = recursive_assign_blocks(sb, pi, data, bm,
					DRAM_ADDR(sih->root), sih->height,
					first_blocknr, last_blocknr,
					address, 0, nvmm, free, alloc_dram);
			if (errval < 0)
				goto fail;
		}
	} else {
		if (height == 0) {
			struct mem_addr *root = (struct mem_addr *)sih->root;
			if (root->nvmm_entry && nvmm) {
				/* With cow we need to re-assign the root */
				struct pmfs_file_write_entry *entry;

				entry = (struct pmfs_file_write_entry *)
					pmfs_get_block(sb, root->nvmm_entry);
				entry->invalid_pages++;
				if (bm)
					clear_bm(root->nvmm, bm, BM_4K);
				if (free)
					pmfs_free_data_blocks(sb, root->nvmm,
						1, pi->i_blk_type, NULL, 1);
				pmfs_dbg_verbose("Free root block @ %lu\n",
						root->nvmm);
				pi->i_blocks--;
			}

			if (alloc_dram) {
				if (!root->page && root->dram == 0) {
					errval = pmfs_new_cache_block(sb, root,
									0, 0);
					if (errval)
						goto fail;
					root->dram |= UNINIT_BIT;
					if (root->nvmm_entry)
						/* Outdate with NVMM */
						root->dram |= OUTDATE_BIT;
				}
			} else {
				if (nvmm) {
					root->nvmm_entry = address;
					assign_nvmm(pi, data, root, bm, 0);
				} else {
					root->dram = address;
				}
			}
			sih->height = height;
			pmfs_dbg_verbose("Set root @%p\n", root);
			return 0;
		}

		if (height > sih->height) {
			errval = pmfs_increase_file_btree_height(sb, sih,
								height);
			if (errval) {
				pmfs_dbg_verbose("Err: inc height %x:%x tot %lx"
					"\n", sih->height, height, total_blocks);
				goto fail;
			}
		}
		errval = recursive_assign_blocks(sb, pi, data, bm,
				DRAM_ADDR(sih->root), height, first_blocknr,
				last_blocknr, address, 0, nvmm, free,
				alloc_dram);
		if (errval < 0)
			goto fail;
	}
	return 0;
fail:
	return errval;
}

/*
 * Assign inode to point to the blocks start from alloc_blocknr.
 */
inline int pmfs_assign_blocks(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_info_header *sih, struct pmfs_file_write_entry *data,
	struct scan_bitmap *bm,	u64 address, bool nvmm, bool free,
	bool alloc_dram)
{
	int errval;
	timing_t assign_time;

	PMFS_START_TIMING(assign_t, assign_time);
	errval = __pmfs_assign_blocks(sb, pi, sih, data, bm, address,
					nvmm, free, alloc_dram);
	PMFS_END_TIMING(assign_t, assign_time);

	return errval;
}

/* Initialize the inode table. The pmfs_inode struct corresponding to the
 * inode table has already been zero'd out */
int pmfs_init_inode_table(struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long init_inode_table_size;

	if (sbi->num_inodes == 0) {
		/* initial inode table size was not specified. */
		if (sbi->initsize >= PMFS_LARGE_INODE_TABLE_THREASHOLD)
			init_inode_table_size = PMFS_LARGE_INODE_TABLE_SIZE;
		else
			init_inode_table_size = PMFS_DEF_BLOCK_SIZE_4K;
	} else {
		init_inode_table_size = sbi->num_inodes << PMFS_INODE_BITS;
	}

	pmfs_memunlock_inode(sb, pi);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;

	/*
	 * Now inodes are resided in dir logs, and inode_table is
	 * only used to save inodes on umount
	 */
	pi->i_blk_type = PMFS_BLOCK_TYPE_4K;

	sbi->s_inodes_count = sbi->num_free_blocks <<
			(pmfs_inode_blk_shift(pi) - PMFS_INODE_BITS);

	/* inode 0 is considered invalid and hence never used */
	sbi->s_free_inodes_count =
		(sbi->s_inodes_count - PMFS_FREE_INODE_HINT_START);
	sbi->s_free_inode_hint = (PMFS_FREE_INODE_HINT_START);

	return 0;
}

int pmfs_init_inode_inuse_list(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_blocknode *blknode;

	blknode = pmfs_alloc_inode_node(sb);
	if (blknode == NULL)
		return -ENOMEM;
	blknode->block_low = 0;
	blknode->block_high = PMFS_FREE_INODE_HINT_START - 1;
	pmfs_insert_blocknode_inodetree(sbi, blknode);
	list_add(&blknode->link, &sbi->inode_inuse_head);
	sbi->num_blocknode_inode = 1;

	return 0;
}

static int pmfs_read_inode(struct super_block *sb, struct inode *inode,
	u64 pi_addr, int rebuild)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode *pi;
	struct pmfs_inode_info_header *sih;
	int ret = -EIO;
	unsigned long ino;

#if 0
	if (pmfs_calc_checksum((u8 *)pi, PMFS_INODE_SIZE)) {
		pmfs_err(inode->i_sb, "checksum error in inode %lx\n",
			  (u64)inode->i_ino);
		goto bad_inode;
	}
#endif

	pi = (struct pmfs_inode *)pmfs_get_block(sb, pi_addr);
	inode->i_mode = le16_to_cpu(pi->i_mode);
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
//	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	pmfs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino >> PMFS_INODE_BITS;

	/* check if the inode is active. */
	if (inode->i_mode == 0 || pi->valid == 0) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	inode->i_mapping->a_ops = &pmfs_aops_xip;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &pmfs_file_inode_operations;
		inode->i_fop = &pmfs_xip_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &pmfs_dir_inode_operations;
		inode->i_fop = &pmfs_dir_operations;
		if (rebuild && inode->i_ino == PMFS_ROOT_INO) {
			sih = pmfs_alloc_header(sb, inode->i_mode);
			pmfs_assign_info_header(sb, ino, sih, 1);
			pmfs_dbg_verbose("%s: rebuild root dir\n", __func__);
			pmfs_rebuild_dir_inode_tree(sb, pi, pi_addr,
					sih, NULL);
			si->header = sih;
		}
		break;
	case S_IFLNK:
		inode->i_op = &pmfs_symlink_inode_operations;
		break;
	default:
		inode->i_size = 0;
		inode->i_op = &pmfs_special_inode_operations;
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

static void pmfs_get_inode_flags(struct inode *inode, struct pmfs_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int pmfs_flags = le32_to_cpu(pi->i_flags);

	pmfs_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		pmfs_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		pmfs_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		pmfs_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		pmfs_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		pmfs_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(pmfs_flags);
}

static void pmfs_update_inode(struct inode *inode, struct pmfs_inode *pi)
{
	pmfs_memunlock_inode(inode->i_sb, pi);
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
	pmfs_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);

	pmfs_memlock_inode(inode->i_sb, pi);
}

static int pmfs_alloc_unused_inode(struct super_block *sb, unsigned long *ino)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->inode_inuse_head);
	struct pmfs_blocknode *i, *next_i;
	struct pmfs_blocknode *free_blocknode = NULL;
	bool found = 0;
	unsigned long next_block_low;
	unsigned long new_block_low;
	unsigned long new_block_high;
	unsigned long MAX_INODE = 1UL << 31;

	list_for_each_entry(i, head, link) {
		if (i->link.next == head) {
			next_i = NULL;
			next_block_low = MAX_INODE;
		} else {
			next_i = list_entry(i->link.next, typeof(*i), link);
			next_block_low = next_i->block_low;
		}

		new_block_low = i->block_high + 1;
		new_block_high = new_block_low;

		if ((new_block_low == (i->block_high + 1)) &&
			(new_block_high == (next_block_low - 1)))
		{
			/* Fill the gap completely */
			if (next_i) {
				i->block_high = next_i->block_high;
				rb_erase(&next_i->node,
					&sbi->inode_inuse_tree);
				list_del(&next_i->link);
				free_blocknode = next_i;
				sbi->num_blocknode_inode--;
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

		/* Should be done in one single step */
		pmfs_dbg("%s: alloc inode error!\n", __func__);
	}

	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);

	if (found == 0) {
		return -ENOSPC;
	}

	*ino = new_block_low;

	pmfs_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

static void pmfs_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->inode_inuse_head);
	unsigned long new_block_low;
	unsigned long new_block_high;
	struct pmfs_blocknode *i = NULL;
	struct pmfs_blocknode *free_blocknode= NULL;
	struct pmfs_blocknode *curr_node;
	unsigned long step = 0;

	new_block_low = ino;
	new_block_high = ino;

	BUG_ON(list_empty(head));

	pmfs_dbg_verbose("Free inuse ino: %lu\n", new_block_low);

	i = pmfs_find_blocknode_inodetree(sbi, new_block_low, &step);
	if (!i) {
		pmfs_dbg("%s ERROR: %lu - %lu not found\n", __func__,
				new_block_low, new_block_high);
		mutex_unlock(&sbi->inode_table_mutex);
		return;
	}

	if ((new_block_low == i->block_low) &&
		(new_block_high == i->block_high)) {
		/* fits entire datablock */
		rb_erase(&i->node, &sbi->inode_inuse_tree);
		list_del(&i->link);
		free_blocknode = i;
		sbi->num_blocknode_inode--;
		goto block_found;
	}
	if ((new_block_low == i->block_low) &&
		(new_block_high < i->block_high)) {
		/* Aligns left */
		i->block_low = new_block_high + 1;
		goto block_found;
	}
	if ((new_block_low > i->block_low) &&
		(new_block_high == i->block_high)) {
		/* Aligns right */
		i->block_high = new_block_low - 1;
		goto block_found;
	}
	if ((new_block_low > i->block_low) &&
		(new_block_high < i->block_high)) {
		/* Aligns somewhere in the middle */
		curr_node = pmfs_alloc_inode_node(sb);
		PMFS_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block*/
			goto block_found;
		}
		curr_node->block_low = new_block_high + 1;
		curr_node->block_high = i->block_high;
		i->block_high = new_block_low - 1;
		pmfs_insert_blocknode_inodetree(sbi, curr_node);
		list_add(&curr_node->link, &i->link);
		goto block_found;
	}

	pmfs_error_mng(sb, "Unable to free inode %lu\n", new_block_low);
	pmfs_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->block_low, i->block_high);
//	dump_stack();

block_found:

//	sbi->s_free_inodes_count++;
	if (free_blocknode)
		__pmfs_free_blocknode(free_blocknode);
	free_steps += step;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 */
static int pmfs_free_inode(struct inode *inode,
	struct pmfs_inode_info_header *sih)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi;
	unsigned long pmfs_ino;
	int err = 0;
	timing_t free_time;

	PMFS_START_TIMING(free_inode_t, free_time);
	mutex_lock(&sbi->inode_table_mutex);

	pmfs_dbgv("free_inode: %lu free_nodes %lu tot nodes %lu hint %lu\n",
		   inode->i_ino, sbi->s_free_inodes_count, sbi->s_inodes_count,
		   sbi->s_free_inode_hint);
	pmfs_ino = inode->i_ino >> PMFS_INODE_BITS;

	pi = pmfs_get_inode(sb, inode);

	if (pi->valid) {
		pmfs_dbg("%s: inode %lu still valid\n",
				__func__, inode->i_ino);
		pi->valid = 0;
	}

	pmfs_free_inode_log(sb, pi);
	sih->pi_addr = 0;

	/* increment s_free_inodes_count */
	if (pmfs_ino < (sbi->s_free_inode_hint))
		sbi->s_free_inode_hint = (pmfs_ino);

	sbi->s_free_inodes_count += 1;

	if ((sbi->s_free_inodes_count) ==
	    (sbi->s_inodes_count) - PMFS_FREE_INODE_HINT_START) {
		/* filesystem is empty */
		pmfs_dbg_verbose("fs is empty!\n");
		sbi->s_free_inode_hint = (PMFS_FREE_INODE_HINT_START);
	}

	pmfs_dbgv("free_inode: free_nodes %lu total_nodes %lu hint %lu\n",
		   sbi->s_free_inodes_count, sbi->s_inodes_count,
		   sbi->s_free_inode_hint);

	pmfs_free_inuse_inode(sb, pmfs_ino);
	mutex_unlock(&sbi->inode_table_mutex);
	PMFS_END_TIMING(free_inode_t, free_time);
	return err;
}

struct inode *pmfs_iget(struct super_block *sb, unsigned long ino)
{
	struct pmfs_inode_info *si;
	struct pmfs_inode_info_header *sih = NULL;
	struct inode *inode;
	int rebuild = 0;
	u64 pi_addr;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	if (ino == PMFS_ROOT_INO) {
		si = PMFS_I(inode);
		sih = pmfs_find_info_header(sb, ino >> PMFS_INODE_BITS);
		if (sih)
			si->header = sih;
		else
			rebuild = 1;
		pi_addr = PMFS_ROOT_INO_START;
	} else {
		si = PMFS_I(inode);
		sih = pmfs_find_info_header(sb, ino >> PMFS_INODE_BITS);
		if (!sih) {
			pmfs_dbg("%s: sih for ino %lu not found!\n",
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
	err = pmfs_read_inode(sb, inode, pi_addr, rebuild);
	if (unlikely(err))
		goto fail;
	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

void pmfs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	__le64 root;
	unsigned long last_blocknr;
	unsigned int height, btype;
	timing_t evict_time;
	int err = 0;
	int freed = 0;

	if (!sih) {
		pmfs_dbg("%s: ino %lu sih is NULL!\n", __func__, inode->i_ino);
		BUG();
	}

	PMFS_START_TIMING(evict_inode_t, evict_time);
	pmfs_dbg_verbose("%s: %lu\n", __func__, inode->i_ino);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
			S_ISLNK(inode->i_mode)))
			goto out;
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		root = sih->root;
		height = sih->height;
		btype = pi->i_blk_type;
		pmfs_dbg_verbose("%s: root 0x%llx, height %u\n",
					__func__, root, height);

		if (pi->i_flags & cpu_to_le32(PMFS_EOFBLOCKS_FL)) {
			last_blocknr = (1UL << (sih->height * META_BLK_SHIFT))
			    - 1;
		} else {
			if (likely(inode->i_size))
				last_blocknr = (inode->i_size - 1) >>
					pmfs_inode_blk_shift(pi);
			else
				last_blocknr = 0;
			last_blocknr = pmfs_sparse_last_blocknr(sih->height,
				last_blocknr);
		}

		/* We need the log to free the blocks from the b-tree */
		switch (inode->i_mode & S_IFMT) {
		case S_IFREG:
			pmfs_dbg_verbose("%s: file ino %lu, root 0x%llx, "
					"height %u\n", __func__, inode->i_ino,
					root, height);
			freed = pmfs_free_file_inode_subtree(sb, root,
					height, btype, last_blocknr);
			break;
		case S_IFDIR:
			pmfs_dbg_verbose("%s: dir ino %lu\n",
					__func__, inode->i_ino);
			pmfs_delete_dir_tree(sb, sih);
			break;
		case S_IFLNK:
			/* Log will be freed later */
			break;
		default:
			pmfs_dbg("%s: unknown\n", __func__);
			break;
		}

		sih->root = 0;
		sih->height = 0;
		pmfs_dbg_verbose("%s: Freed %d\n", __func__, freed);
		/* Then we can free the inode */
		err = pmfs_free_inode(inode, sih);
		if (err)
			goto out;
		pi = NULL; /* we no longer own the pmfs_inode */

		inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
		inode->i_size = 0;
	}
out:
	/* TODO: Since we don't use page-cache, do we really need the following
	 * call? */
	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
	PMFS_END_TIMING(evict_inode_t, evict_time);
}

/* Returns 0 on failure */
u64 pmfs_new_pmfs_inode(struct super_block *sb,
	struct pmfs_inode_info_header **return_sih)
{
	struct pmfs_inode_info_header *sih;
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long free_ino = 0;
	u64 ino = 0;
	int i, ret;

	mutex_lock(&sbi->inode_table_mutex);
	ret = pmfs_alloc_unused_inode(sb, &free_ino);
	if (ret) {
		pmfs_dbg("%s: alloc inode failed %d\n", __func__, ret);
		mutex_unlock(&sbi->inode_table_mutex);
		return 0;
	}

	sbi->s_free_inodes_count -= 1;

	i = (sbi->s_free_inode_hint);
	if (i < (sbi->s_inodes_count) - 1)
		sbi->s_free_inode_hint = (i + 1);
	else
		sbi->s_free_inode_hint = (PMFS_FREE_INODE_HINT_START);

	sih = pmfs_alloc_header(sb, 0);
	pmfs_assign_info_header(sb, free_ino, sih, 0);

	mutex_unlock(&sbi->inode_table_mutex);
	ino = free_ino << PMFS_INODE_BITS;
	*return_sih = sih;
	return ino;
}

struct inode *pmfs_new_vfs_inode(enum pmfs_new_inode_type type,
	struct inode *dir, u64 pi_addr,
	struct pmfs_inode_info_header *sih, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr)
{
	struct super_block *sb;
	struct pmfs_sb_info *sbi;
	struct inode *inode;
	struct pmfs_inode *diri = NULL;
	struct pmfs_inode_info *si;
	struct pmfs_inode *pi;
	int pmfs_ino, errval;
	timing_t new_inode_time;

	PMFS_START_TIMING(new_inode_t, new_inode_time);
	sb = dir->i_sb;
	sbi = (struct pmfs_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;

	pmfs_dbgv("inode: %p free_inodes %lu total_inodes %lu hint %lu\n",
		inode, sbi->s_free_inodes_count, sbi->s_inodes_count,
		sbi->s_free_inode_hint);

	diri = pmfs_get_inode(sb, dir);
	if (!diri)
		return ERR_PTR(-EACCES);

	pmfs_ino = ino >> PMFS_INODE_BITS;

	pi = (struct pmfs_inode *)pmfs_get_block(sb, pi_addr);
	pmfs_dbg_verbose("%s: allocating inode %llu @ 0x%llx\n",
					__func__, ino, pi_addr);

	/* chosen inode is in ino */
	inode->i_ino = ino;

	switch (type) {
		case TYPE_CREATE:
			inode->i_op = &pmfs_file_inode_operations;
			inode->i_mapping->a_ops = &pmfs_aops_xip;
			inode->i_fop = &pmfs_xip_file_operations;
			break;
		case TYPE_MKNOD:
			init_special_inode(inode, mode, rdev);
			inode->i_op = &pmfs_special_inode_operations;
			break;
		case TYPE_SYMLINK:
			inode->i_op = &pmfs_symlink_inode_operations;
			inode->i_mapping->a_ops = &pmfs_aops_xip;
			break;
		case TYPE_MKDIR:
			inode->i_op = &pmfs_dir_inode_operations;
			inode->i_fop = &pmfs_dir_operations;
			inode->i_mapping->a_ops = &pmfs_aops_xip;
			set_nlink(inode, 2);
			break;
		default:
			pmfs_dbg("Unknown new inode type %d\n", type);
			break;
	}

	/*
	 * Pi is part of the dir log so no transaction is needed,
	 * but we need to flush to NVMM.
	 */
	pmfs_memunlock_inode(sb, pi);
	pi->i_blk_type = PMFS_DEFAULT_BLOCK_TYPE;
	pi->i_flags = pmfs_mask_flags(mode, diri->i_flags);
	pi->log_head = 0;
	pi->log_tail = 0;
	pi->pmfs_ino = pmfs_ino;
	pi->valid = 1;
	pmfs_memlock_inode(sb, pi);

	si = PMFS_I(inode);
	sih->i_mode = inode->i_mode;
	sih->pi_addr = pi_addr;
	si->header = sih;

	pmfs_update_inode(inode, pi);

	pmfs_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));

	if (insert_inode_locked(inode) < 0) {
		pmfs_err(sb, "pmfs_new_inode failed ino %lx\n", inode->i_ino);
		errval = -EINVAL;
		goto fail1;
	}

	pmfs_flush_buffer(&pi, PMFS_INODE_SIZE, 0);
	PMFS_END_TIMING(new_inode_t, new_inode_time);
	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
	PMFS_END_TIMING(new_inode_t, new_inode_time);
	return ERR_PTR(errval);
}

/* This function checks if VFS's inode and PMFS's inode are not in sync */
static bool pmfs_is_inode_dirty(struct inode *inode, struct pmfs_inode *pi)
{
	bool retval = false;

	/* Time and size are rebuilt upon recovery */
#if 0
	if (inode->i_ctime.tv_sec != le32_to_cpu(pi->i_ctime) ||
		inode->i_mtime.tv_sec != le32_to_cpu(pi->i_mtime) ||
		inode->i_atime.tv_sec != le32_to_cpu(pi->i_atime)) {
			printk_ratelimited(KERN_ERR "dirty check: "
						"time not sync\n");
			retval = true;
	}

	if (inode->i_size != le64_to_cpu(pi->i_size)) {
			printk_ratelimited(KERN_ERR "dirty check: "
						"size not sync\n");
			retval = true;
	}
#endif

	if (inode->i_blocks != le64_to_cpu(pi->i_blocks)) {
			printk_ratelimited(KERN_ERR "dirty check: "
						"blocks not sync\n");
			retval = true;
	}

	if (inode->i_mode != le16_to_cpu(pi->i_mode) ||
		i_uid_read(inode) != le32_to_cpu(pi->i_uid) ||
		i_gid_read(inode) != le32_to_cpu(pi->i_gid) ||
		inode->i_nlink != le16_to_cpu(pi->i_links_count)) {
			printk_ratelimited(KERN_ERR "dirty check: "
						"mode not sync\n");
			retval = true;
	}
	return retval;
}

int pmfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called. */
	BUG();
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because PMFS always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void pmfs_dirty_inode(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);

	/* only i_atime should have changed if at all.
	 * we can do in-place atomic update */
	pmfs_memunlock_inode(sb, pi);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pmfs_memlock_inode(sb, pi);
	pmfs_flush_buffer(&pi->i_atime, sizeof(pi->i_atime), true);

	/* FIXME: Is this check needed? */
	if (pmfs_is_inode_dirty(inode, pi))
		printk_ratelimited(KERN_ERR "pmfs: inode was dirty! "
			"inode %lu blocks, pi %llu blocks, "
			"inode size %llu, pi size %llu, "
			"inode link %u, pi link %u\n",
			inode->i_blocks, pi->i_blocks,
			inode->i_size, pi->i_size,
			inode->i_nlink, pi->i_links_count);
}

/*
 * Called to zeros out a single block. It's used in the "resize"
 * to avoid to keep data in case the file grow up again.
 */
/* Make sure to zero out just a single 4K page in case of 2M or 1G blocks */
static void pmfs_block_truncate_page(struct inode *inode, loff_t newsize)
{
	struct super_block *sb = inode->i_sb;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long blocknr, length;
	u64 blockoff;
	char *bp;

	/* Block boundary or extending ? */
	if (!offset || newsize > inode->i_size)
		return;

	length = sb->s_blocksize - offset;
	blocknr = newsize >> sb->s_blocksize_bits;

	blockoff = pmfs_find_nvmm_block(inode, blocknr);

	/* Hole ? */
	if (!blockoff)
		return;

	bp = pmfs_get_block(sb, blockoff);
	pmfs_memunlock_block(sb, bp);
	memset(bp + offset, 0, length);
	pmfs_memlock_block(sb, bp);
}

static void pmfs_setsize(struct inode *inode, loff_t oldsize, loff_t newsize)
{
	/* We only support truncate regular file */
	if (!(S_ISREG(inode->i_mode))) {
		pmfs_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
		return;
	}

	pmfs_dbgv("%s: inode %lu, old size %llu, new size %llu\n",
		__func__, inode->i_ino, oldsize, newsize);

	if (newsize != oldsize) {
		pmfs_block_truncate_page(inode, newsize);
		i_size_write(inode, newsize);
	}
	/* FIXME: we should make sure that there is nobody reading the inode
	 * before truncating it. Also we need to munmap the truncated range
	 * from application address space, if mmapped. */
	/* synchronize_rcu(); */
	__pmfs_truncate_file_blocks(inode, newsize, oldsize);
}

int pmfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		         struct kstat *stat)
{
	struct inode *inode;

	inode = dentry->d_inode;
	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}

static void pmfs_update_setattr_entry(struct inode *inode,
	struct pmfs_setattr_logentry *entry, struct iattr *attr)
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

	pmfs_flush_buffer(entry, sizeof(struct pmfs_setattr_logentry), 0);
}

void pmfs_apply_setattr_entry(struct pmfs_inode *pi,
	struct pmfs_setattr_logentry *entry)
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
u64 pmfs_append_setattr_entry(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, struct iattr *attr, u64 tail)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct pmfs_setattr_logentry *entry;
	u64 curr_p, new_tail = 0;
	size_t size = sizeof(struct pmfs_setattr_logentry);
	timing_t append_time;

	PMFS_START_TIMING(append_entry_t, append_time);
	pmfs_dbg_verbose("%s: inode %lu attr change\n",
				__func__, inode->i_ino);

	curr_p = pmfs_get_append_head(sb, pi, sih, tail, size, 0, 1);
	if (curr_p == 0)
		BUG();

	entry = (struct pmfs_setattr_logentry *)pmfs_get_block(sb, curr_p);
	/* inode is already updated with attr */
	pmfs_update_setattr_entry(inode, entry, attr);
	new_tail = curr_p + size;

	PMFS_END_TIMING(append_entry_t, append_time);
	return new_tail;
}

int pmfs_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	int ret;
	unsigned int ia_valid = attr->ia_valid, attr_mask;
	loff_t oldsize = inode->i_size;
	u64 new_tail;
	timing_t setattr_time;

	PMFS_START_TIMING(setattr_t, setattr_time);
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
	new_tail = pmfs_append_setattr_entry(sb, pi, inode, attr, 0);

	pmfs_update_tail(pi, new_tail);

	/* Only after log entry is committed, we can truncate size */
	if ((ia_valid & ATTR_SIZE) && (attr->ia_size != oldsize ||
			pi->i_flags & cpu_to_le32(PMFS_EOFBLOCKS_FL))) {
//		pmfs_set_blocksize_hint(sb, inode, pi, attr->ia_size);

		/* now we can freely truncate the inode */
		pmfs_setsize(inode, oldsize, attr->ia_size);
	}

	PMFS_END_TIMING(setattr_t, setattr_time);
	return ret;
}

void pmfs_set_inode_flags(struct inode *inode, struct pmfs_inode *pi,
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

static ssize_t pmfs_direct_IO(int rw, struct kiocb *iocb,
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

	PMFS_START_TIMING(direct_IO_t, dio_time);
	for (seg = 0; seg < nr_segs; seg++) {
		end += iv->iov_len;
		iv++;
	}

	if ((rw == WRITE) && end > i_size_read(inode)) {
		/* FIXME: Do we need to check for out of bounds IO for R/W */
		printk(KERN_ERR "pmfs: needs to grow (size = %lld)\n", end);
		return err;
	}

	pmfs_dbg_verbose("%s\n", __func__);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (rw == READ) {
			err = pmfs_xip_file_read(filp, iv->iov_base,
					iv->iov_len, &offset);
		} else if (rw == WRITE) {
			err = pmfs_cow_file_write(filp, iv->iov_base,
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
		printk(KERN_ERR "pmfs: direct_IO: end = %lld"
			"but offset = %lld\n", end, offset);
err:
	PMFS_END_TIMING(direct_IO_t, dio_time);
	return err;
}

#else

static ssize_t pmfs_direct_IO(struct kiocb *iocb,
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

	PMFS_START_TIMING(direct_IO_t, dio_time);
	end = offset + count;

	if ((iov_iter_rw(iter) == WRITE) && end > i_size_read(inode)) {
		/* FIXME: Do we need to check for out of bounds IO for R/W */
		printk(KERN_ERR "pmfs: needs to grow (size = %lld)\n", end);
		return err;
	}

	pmfs_dbg_verbose("%s\n", __func__);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			err = pmfs_xip_file_read(filp, iv->iov_base,
					iv->iov_len, &offset);
		} else if (iov_iter_rw(iter) == WRITE) {
			err = pmfs_cow_file_write(filp, iv->iov_base,
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
		printk(KERN_ERR "pmfs: direct_IO: end = %lld"
			"but offset = %lld\n", end, offset);
err:
	PMFS_END_TIMING(direct_IO_t, dio_time);
	return err;
}

#endif

static int pmfs_coalesce_log_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long first_blocknr,
	unsigned long num_pages)
{
	unsigned long next_blocknr;
	u64 curr_block;
	struct pmfs_inode_log_page *curr_page;
	int i;

	if (prev_blocknr) {
		/* Link prev block and newly allocated head block */
		curr_block = pmfs_get_block_off(sb, prev_blocknr,
						PMFS_BLOCK_TYPE_4K);
		curr_page = (struct pmfs_inode_log_page *)
				pmfs_get_block(sb, curr_block);
		curr_page->page_tail.next_page = pmfs_get_block_off(sb,
				first_blocknr, PMFS_BLOCK_TYPE_4K);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = pmfs_get_block_off(sb, first_blocknr,
						PMFS_BLOCK_TYPE_4K);
	curr_page = (struct pmfs_inode_log_page *)
				pmfs_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		curr_page->page_tail.next_page = pmfs_get_block_off(sb,
				next_blocknr, PMFS_BLOCK_TYPE_4K);
		curr_page++;
		next_blocknr++;
	}

	return 0;
}

/* Log block resides in NVMM */
int pmfs_allocate_inode_log_pages(struct super_block *sb,
	struct pmfs_inode *pi, unsigned long num_pages,
	u64 *new_block)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = pmfs_new_log_blocks(sb, pi->pmfs_ino, &new_inode_blocknr,
					num_pages, PMFS_BLOCK_TYPE_4K, 1);

	if (allocated <= 0) {
		pmfs_err(sb, "ERROR: no inode log page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	ret_pages += allocated;
	num_pages -= allocated;
	pmfs_dbg_verbose("Pi %llu: Alloc %d log blocks @ 0x%lx\n",
			pi->pmfs_ino, allocated, new_inode_blocknr);

	/* Coalesce the pages */
	pmfs_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated);
	first_blocknr = new_inode_blocknr;
	prev_blocknr = new_inode_blocknr + allocated - 1;

	/* Allocate remaining pages */
	while (num_pages) {
		allocated = pmfs_new_log_blocks(sb, pi->pmfs_ino,
					&new_inode_blocknr, num_pages,
					PMFS_BLOCK_TYPE_4K, 1);

		pmfs_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			pmfs_err(sb, "ERROR: no inode log page available: "
				"%d %d\n", num_pages, allocated);
			return allocated;
		}
		ret_pages += allocated;
		num_pages -= allocated;
		pmfs_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr,
						allocated);
		prev_blocknr = new_inode_blocknr + allocated - 1;
	}

	*new_block = pmfs_get_block_off(sb, first_blocknr,
						PMFS_BLOCK_TYPE_4K);

	return ret_pages;
}

/*
 * Copy alive log entries to the new log,
 * merge entries if possible
 */
#if 0
int pmfs_inode_log_gabbage_collection(struct super_block *sb,
	struct pmfs_inode *pi, u64 new_block, unsigned long num_pages)
{
	struct pmfs_file_write_entry *curr_entry, *new_entry;
	u64 old_head, new_head;
	struct pmfs_inode_log_page *last_page;
	size_t entry_size = sizeof(struct pmfs_file_write_entry);

	old_head = pi->log_head;
	new_head = new_block;
	last_page = (struct pmfs_inode_log_page *)
		pmfs_get_block(sb, new_block + ((num_pages - 1) << PAGE_SHIFT));

	while (old_head != pi->log_tail) {
		if (is_last_entry(old_head))
			old_head = next_log_page(sb, old_head);
		if (is_last_entry(new_head))
			new_head = next_log_page(sb, new_head);

		if (old_head == pi->log_tail)
			break;

		curr_entry = pmfs_get_block(sb, old_head);
		if (curr_entry->num_pages == curr_entry->invalid_pages) {
			goto update;
		}
		new_entry = pmfs_get_block(sb, new_head);
		memcpy(new_entry, curr_entry, entry_size);
update:
		old_head += entry_size;
		new_head += entry_size;
	}

	last_page->page_tail.next_page = pi->log_head;
	pmfs_flush_buffer(pmfs_get_block(sb, new_block),
				num_pages * PAGE_SIZE, 1);
	return 0;
}
#endif

static bool curr_page_invalid(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_log_page *curr_page)
{
	struct pmfs_file_write_entry *entry;
	int i;
	timing_t check_time;

	PMFS_START_TIMING(check_invalid_t, check_time);
	for (i = 0; i < ENTRIES_PER_PAGE; i++) {
		entry = &curr_page->entries[i];
		/* Do not recycle inode change entry */
		if (pmfs_get_entry_type(entry) != FILE_WRITE) {
			PMFS_END_TIMING(check_invalid_t, check_time);
			return false;
		}
		if (entry->num_pages != entry->invalid_pages) {
			PMFS_END_TIMING(check_invalid_t, check_time);
			return false;
		}
	}

	PMFS_END_TIMING(check_invalid_t, check_time);
	return true;
}

static void free_curr_page(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_log_page *curr_page,
	struct pmfs_inode_log_page *last_page, u64 curr_head)
{
	unsigned short btype = pi->i_blk_type;

	last_page->page_tail.next_page = curr_page->page_tail.next_page;
	pmfs_flush_buffer(&last_page->page_tail.next_page, CACHELINE_SIZE, 1);
	pmfs_free_log_blocks(sb, pmfs_get_blocknr(sb, curr_head, btype),
					1, btype, NULL, 1);
}

int pmfs_inode_log_garbage_collection(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_inode_info_header *sih,
	u64 curr_tail, u64 new_block, int num_pages)
{
	u64 curr, next, possible_head = 0;
	int found_head = 0;
	struct pmfs_inode_log_page *last_page = NULL;
	struct pmfs_inode_log_page *curr_page = NULL;
	int first_need_free = 0;
	unsigned short btype = pi->i_blk_type;
	int freed_pages = 0;
	timing_t gc_time;

	PMFS_START_TIMING(log_gc_t, gc_time);
	curr = pi->log_head;

	pmfs_dbg_verbose("%s: log head 0x%llx, tail 0x%llx\n",
				__func__, curr, curr_tail);
	while (1) {
		if (curr >> PAGE_SHIFT == pi->log_tail >> PAGE_SHIFT) {
			/* Don't recycle tail page */
			if (found_head == 0)
				possible_head = cpu_to_le64(curr);
			break;
		}

		curr_page = (struct pmfs_inode_log_page *)
					pmfs_get_block(sb, curr);
		next = curr_page->page_tail.next_page;
		pmfs_dbg_verbose("curr 0x%llx, next 0x%llx\n", curr, next);
		if (curr_page_invalid(sb, pi, curr_page)) {
			pmfs_dbg_verbose("curr page %p invalid\n", curr_page);
			if (curr == pi->log_head) {
				/* Free first page later */
				first_need_free = 1;
				last_page = curr_page;
			} else {
				pmfs_dbg_verbose("Free log block 0x%llx\n",
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

	((struct pmfs_inode_page_tail *)
		pmfs_get_block(sb, curr_tail))->next_page = new_block;

	curr = pi->log_head;

	/* FIXME: This should be atomic */
	pi->log_head = possible_head;
	pmfs_dbg_verbose("%s: %d new head 0x%llx\n", __func__,
					found_head, possible_head);
	pmfs_dbg_verbose("Num pages %d, freed %d\n", num_pages, freed_pages);
	sih->log_pages += num_pages - freed_pages;
	/* Don't update log tail pointer here */
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	if (first_need_free) {
		pmfs_dbg_verbose("Free log head block 0x%llx\n",
					curr >> PAGE_SHIFT);
		pmfs_free_log_blocks(sb, pmfs_get_blocknr(sb, curr, btype),
					1, btype, NULL, 1);
	}
	PMFS_END_TIMING(log_gc_t, gc_time);
	return 0;
}

u64 pmfs_extend_inode_log(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_info_header *sih, u64 curr_p, int is_file)
{
	u64 new_block;
	int allocated;
	unsigned long num_pages;
	u64 page_tail;

	if (curr_p == 0) {
		allocated = pmfs_allocate_inode_log_pages(sb, pi,
					1, &new_block);
		if (allocated != 1) {
			pmfs_err(sb, "ERROR: no inode log page "
					"available\n");
			return 0;
		}
		/* FIXME: Make this atomic */
		pi->log_head = new_block;
		pi->log_tail = new_block;
		sih->log_pages = 1;
		pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
	} else {
		num_pages = sih->log_pages >= 256 ?
				256 : sih->log_pages;
//		pmfs_dbg("Before append log pages:\n");
//		pmfs_print_inode_log_page(sb, inode);
		allocated = pmfs_allocate_inode_log_pages(sb, pi,
					num_pages, &new_block);
		pmfs_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
		if (allocated <= 0) {
			pmfs_err(sb, "ERROR: no inode log page "
					"available\n");
			return 0;
		}

		if (is_file) {
			pmfs_inode_log_garbage_collection(sb, pi, sih, curr_p,
						new_block, allocated);
		} else {
			/* FIXME: Disable GC for dir inode by now */
			page_tail = (curr_p & ~INVALID_MASK) + LAST_ENTRY;
			((struct pmfs_inode_page_tail *)
				pmfs_get_block(sb, page_tail))->next_page
								= new_block;
			sih->log_pages += num_pages;
		}

//		pmfs_dbg("After append log pages:\n");
//		pmfs_print_inode_log_page(sb, inode);
		/* Atomic switch to new log */
//		pmfs_switch_to_new_log(sb, pi, new_block, num_pages);
	}
	return new_block;
}

u64 pmfs_get_append_head(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_info_header *sih, u64 tail, size_t size,
	int new_inode, int is_file)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else
		curr_p = pi->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, new_inode) &&
				next_log_page(sb, curr_p) == 0)) {
		curr_p = pmfs_extend_inode_log(sb, pi, sih, curr_p, is_file);
		if (curr_p == 0)
			return 0;
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	return  curr_p;
}

/*
 * Append a pmfs_file_write_entry to the current pmfs_inode_log_page.
 * FIXME: Must hold inode->i_mutex. Convert it to lock-free.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 */
u64 pmfs_append_file_write_entry(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, struct pmfs_file_write_entry *data, u64 tail)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct pmfs_file_write_entry *entry;
	u64 curr_p;
	size_t size = sizeof(struct pmfs_file_write_entry);
	timing_t append_time;

	PMFS_START_TIMING(append_entry_t, append_time);

	curr_p = pmfs_get_append_head(sb, pi, sih, tail, size, 0, 1);
	if (curr_p == 0)
		BUG();

	entry = (struct pmfs_file_write_entry *)pmfs_get_block(sb, curr_p);
	__copy_from_user_inatomic_nocache(entry, data,
				sizeof(struct pmfs_file_write_entry));
	pmfs_dbg_verbose("file %lu entry @ 0x%llx: pgoff %u, num %u, "
			"block %llu, size %llu\n", inode->i_ino,
			curr_p, entry->pgoff, entry->num_pages,
			entry->block >> PAGE_SHIFT, entry->size);
	/* entry->invalid is set to 0 */

	PMFS_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

void pmfs_free_inode_log(struct super_block *sb, struct pmfs_inode *pi)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode_log_page *curr_page;
	u64 curr_block;
	unsigned long blocknr, start_blocknr = 0;
	int num_free = 0;
	u32 btype = pi->i_blk_type;
	struct pmfs_blocknode *start_hint = NULL;

	if (pi->log_head == 0 || pi->log_tail == 0)
		return;

	curr_block = pi->log_head;
	mutex_lock(&sbi->s_lock);
	while (curr_block) {
		curr_page = (struct pmfs_inode_log_page *)pmfs_get_block(sb,
							curr_block);
		blocknr = pmfs_get_blocknr(sb, le64_to_cpu(curr_block),
				    btype);
		pmfs_dbg_verbose("%s: free page %llu\n", __func__, curr_block);
		curr_block = curr_page->page_tail.next_page;

		if (start_blocknr == 0) {
			start_blocknr = blocknr;
			num_free = 1;
		} else {
			if (blocknr == start_blocknr + num_free) {
				num_free++;
			} else {
				/* A new start */
				pmfs_free_log_blocks(sb, start_blocknr,
					num_free, btype, &start_hint, 0);
				start_blocknr = blocknr;
				num_free = 1;
			}
		}
	}
	pmfs_free_log_blocks(sb, start_blocknr,	num_free, btype,
					&start_hint, 0);
	mutex_unlock(&sbi->s_lock);

	/* FIXME: make this atomic */
	pi->log_head = pi->log_tail = 0;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
}

int pmfs_free_dram_resource(struct super_block *sb,
	struct pmfs_inode_info_header *sih)
{
	int freed = 0;
	unsigned long last_blocknr;

	if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode)))
		return 0;

	if (likely(sih->i_size))
		last_blocknr = (sih->i_size - 1) >> PAGE_SHIFT;
	else
		last_blocknr = 0;

	last_blocknr = pmfs_sparse_last_blocknr(sih->height,
		last_blocknr);
	pmfs_dbg_verbose("%s: height %u, root 0x%llx, "
				"last block %lu\n", __func__,
				sih->height, sih->root, last_blocknr);
	if (S_ISREG(sih->i_mode)) {
		freed = pmfs_free_file_meta_blocks(sb, sih,
						last_blocknr);
	} else {
		pmfs_delete_dir_tree(sb, sih);
		freed = 1;
	}

	return freed;
}

static inline void pmfs_rebuild_file_time_and_size(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_file_write_entry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = cpu_to_le32(entry->mtime);
	pi->i_mtime = cpu_to_le32(entry->mtime);
	pi->i_size = cpu_to_le64(entry->size);
}

int pmfs_rebuild_file_inode_tree(struct super_block *sb,
	struct pmfs_inode *pi, u64 pi_addr,
	struct pmfs_inode_info_header *sih, struct scan_bitmap *bm)
{
	struct pmfs_file_write_entry *entry = NULL;
	struct pmfs_setattr_logentry *attr_entry = NULL;
	struct pmfs_link_change_entry *link_change_entry = NULL;
	struct pmfs_inode_log_page *curr_page;
	u64 ino = pi->pmfs_ino << PMFS_INODE_BITS;
	void *addr;
	u64 curr_p;
	u64 next;
	u8 type;

	pmfs_dbg_verbose("Rebuild file inode %llu tree\n", ino);
	/*
	 * We will regenerate the tree during blocks assignment.
	 * Set height to 0.
	 */
	sih->root = 0;
	sih->height = 0;
	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
	pmfs_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
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
				sizeof(struct pmfs_file_write_entry), 0)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
			if (bm) {
				BUG_ON(curr_p & (PAGE_SIZE - 1));
				set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
			}
		}

		if (curr_p == 0) {
			pmfs_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}

		addr = (void *)pmfs_get_block(sb, curr_p);
		type = pmfs_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				attr_entry =
					(struct pmfs_setattr_logentry *)addr;
				pmfs_apply_setattr_entry(pi, attr_entry);
				curr_p += sizeof(struct pmfs_setattr_logentry);
				continue;
			case LINK_CHANGE:
				link_change_entry =
					(struct pmfs_link_change_entry *)addr;
				pmfs_apply_link_change_entry(pi,
							link_change_entry);
				curr_p += sizeof(struct pmfs_link_change_entry);
				continue;
			case FILE_WRITE:
				break;
			default:
				pmfs_dbg("%s: unknown type %d, 0x%llx\n",
							__func__, type, curr_p);
				PMFS_ASSERT(0);
		}

		entry = (struct pmfs_file_write_entry *)addr;
//		pmfs_print_inode_entry(entry);

		if (entry->num_pages != entry->invalid_pages) {
			/*
			 * The overlaped blocks are already freed.
			 * Don't double free them, just re-assign the pointers.
			 */
			pmfs_assign_blocks(sb, pi, sih, entry, bm, curr_p, true,
					false, false);
		}

		pmfs_rebuild_file_time_and_size(sb, pi, entry);
		curr_p += sizeof(struct pmfs_file_write_entry);
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le16_to_cpu(pi->i_mode);
	pmfs_flush_buffer(pi, sizeof(struct pmfs_inode), 1);

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	curr_page = (struct pmfs_inode_log_page *)pmfs_get_block(sb, curr_p);
	while ((next = curr_page->page_tail.next_page) != 0) {
		sih->log_pages++;
		curr_p = next;
		if (bm) {
			BUG_ON(curr_p & (PAGE_SIZE - 1));
			set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
		}
		curr_page = (struct pmfs_inode_log_page *)
			pmfs_get_block(sb, curr_p);
	}

//	pmfs_print_inode_log_page(sb, inode);
	return 0;
}

const struct address_space_operations pmfs_aops_xip = {
	.direct_IO		= pmfs_direct_IO,
	/*.xip_mem_protect	= pmfs_xip_mem_protect,*/
};
