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

static unsigned long alive_inode;
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

inline int pmfs_rbtree_compare_bmentry(struct multi_set_entry *curr,
	unsigned long bit)
{
	if (bit < curr->bit_low)
		return -1;
	if (bit > curr->bit_high)
		return 1;

	return 0;
}

static int pmfs_find_bmentry(struct single_scan_bm *scan_bm,
	unsigned long bit, struct multi_set_entry **entry)
{
	struct multi_set_entry *curr;
	struct rb_node *temp;
	int compVal;

	temp = scan_bm->multi_set_tree.rb_node;

	while (temp) {
		curr = container_of(temp, struct multi_set_entry, node);
		compVal = pmfs_rbtree_compare_bmentry(curr, bit);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			*entry = curr;
			return 1;
		}
	}

	return 0;
}

static int pmfs_insert_bmentry(struct single_scan_bm *scan_bm,
	struct multi_set_entry *entry)
{
	struct multi_set_entry *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(scan_bm->multi_set_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct multi_set_entry, node);
		compVal = pmfs_rbtree_compare_bmentry(curr, entry->bit_low);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			pmfs_dbg("%s: entry %lu - %lu already exists\n",
				__func__, entry->bit_low, entry->bit_high);
			return -EINVAL;
		}
	}

	rb_link_node(&entry->node, parent, temp);
	rb_insert_color(&entry->node, &scan_bm->multi_set_tree);
	scan_bm->num_entries++;
	return 0;
}

static void pmfs_try_merge_bmentry(struct single_scan_bm *scan_bm,
	struct multi_set_entry *curr_entry)
{
	struct rb_node *prev, *next;
	struct multi_set_entry *prev_entry, *next_entry;

	prev = rb_prev(&curr_entry->node);
	if (prev) {
		prev_entry = rb_entry(prev, struct multi_set_entry, node);
		if (prev_entry->bit_high >= curr_entry->bit_low) {
			pmfs_dbg("%s: ERROR: entry overlap: prev low %lu, "
				"high %lu, curr low %lu, high %lu\n", __func__,
				prev_entry->bit_low, prev_entry->bit_high,
				curr_entry->bit_low, curr_entry->bit_high);
			return;
		}
		if (prev_entry->bit_high + 1 == curr_entry->bit_low &&
				prev_entry->refcount == curr_entry->refcount) {
			rb_erase(&curr_entry->node, &scan_bm->multi_set_tree);
			prev_entry->bit_high = curr_entry->bit_high;
			kmem_cache_free(pmfs_bmentry_cachep, curr_entry);
			curr_entry = prev_entry;
			scan_bm->num_entries--;
		}
	}

	next = rb_next(&curr_entry->node);
	if (next) {
		next_entry = rb_entry(next, struct multi_set_entry, node);
		if (curr_entry->bit_high >= next_entry->bit_low) {
			pmfs_dbg("%s: ERROR: entry overlap: curr low %lu, "
				"high %lu, next low %lu, high %lu\n", __func__,
				curr_entry->bit_low, curr_entry->bit_high,
				next_entry->bit_low, next_entry->bit_high);
			return;
		}
		if (curr_entry->bit_high + 1 == next_entry->bit_low &&
				curr_entry->refcount == next_entry->refcount) {
			rb_erase(&next_entry->node, &scan_bm->multi_set_tree);
			curr_entry->bit_high = next_entry->bit_high;
			kmem_cache_free(pmfs_bmentry_cachep, next_entry);
			scan_bm->num_entries--;
		}
	}
}

static void pmfs_insert_bit_range_to_tree(struct single_scan_bm *scan_bm,
	unsigned long bit_low, unsigned long bit_high, int refcount,
	int try_merge)
{
	struct multi_set_entry *entry;

	if (bit_low > bit_high || refcount < 2) {
		pmfs_dbg("%s: insert invalid range: low %lu, high %lu, "
			"refcount %d\n", __func__, bit_low, bit_high,
			refcount);
		return;
	}

	entry = kmem_cache_alloc(pmfs_bmentry_cachep, GFP_NOFS);
	if (!entry)
		PMFS_ASSERT(0);

	entry->bit_low = bit_low;
	entry->bit_high = bit_high;
	entry->refcount = refcount;
	pmfs_insert_bmentry(scan_bm, entry);
	if (try_merge)
		pmfs_try_merge_bmentry(scan_bm, entry);
}

static void pmfs_inc_bit_in_bmentry(struct single_scan_bm *scan_bm,
	unsigned long bit, struct multi_set_entry *entry)
{
	unsigned long new_bit_low, new_bit_high;

	/* Single bit entry */
	if (bit == entry->bit_low && bit == entry->bit_high) {
		entry->refcount++;
		return;
	}

	/* Align to left */
	if (bit == entry->bit_low) {
		entry->bit_low++;
		pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 1);
		return;
	}

	/* Align to right */
	if (bit == entry->bit_high) {
		entry->bit_high--;
		pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 1);
		return;
	}

	/* In the middle. Break the entry and insert new ones */
	new_bit_low = bit + 1;
	new_bit_high = entry->bit_high;
	entry->bit_high = bit - 1;

	pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 0);

	pmfs_insert_bit_range_to_tree(scan_bm, new_bit_low, new_bit_high,
					entry->refcount, 0);
}

static void set_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry;
	int found = 0;

	if (test_and_set_bit(bit, scan_bm->bitmap) == 0)
		return;

	pmfs_dbgv("%s: type %d, bit %lu exists\n", __func__, type, bit);

	if (scan_bm->num_entries) {
		found = pmfs_find_bmentry(scan_bm, bit, &entry);
		if (found == 1) {
			pmfs_inc_bit_in_bmentry(scan_bm, bit, entry);
			return;
		}
	}

	pmfs_insert_bit_range_to_tree(scan_bm, bit, bit, 2, 1);
}

static void pmfs_dec_bit_in_bmentry(struct single_scan_bm *scan_bm,
	unsigned long bit, struct multi_set_entry *entry)
{
	unsigned long new_bit_low, new_bit_high;

	/* Single bit entry */
	if (bit == entry->bit_low && bit == entry->bit_high) {
		entry->refcount--;
		if (entry->refcount == 1) {
			rb_erase(&entry->node, &scan_bm->multi_set_tree);
			kmem_cache_free(pmfs_bmentry_cachep, entry);
			scan_bm->num_entries--;
		}
		return;
	}

	/* Align to left */
	if (bit == entry->bit_low) {
		entry->bit_low++;
		if (entry->refcount == 2)
			return;
		pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 1);
		return;
	}

	/* Align to right */
	if (bit == entry->bit_high) {
		entry->bit_high--;
		if (entry->refcount == 2)
			return;
		pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 1);
		return;
	}

	/* In the middle. Break the entry and insert new ones */
	new_bit_low = bit + 1;
	new_bit_high = entry->bit_high;
	entry->bit_high = bit - 1;

	if (entry->refcount > 2)
		pmfs_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 0);

	pmfs_insert_bit_range_to_tree(scan_bm, new_bit_low, new_bit_high,
					entry->refcount, 0);
}

static void clear_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry;
	int found = 0;

	if (scan_bm->num_entries) {
		found = pmfs_find_bmentry(scan_bm, bit, &entry);
		if (found == 1) {
			pmfs_dec_bit_in_bmentry(scan_bm, bit, entry);
			return;
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

static int get_cpuid(struct pmfs_sb_info *sbi, unsigned long blocknr)
{
	int cpuid;

	cpuid = blocknr / sbi->per_list_blocks;

	if (cpuid >= sbi->cpus)
		cpuid = SHARED_CPU;

	return cpuid;
}

static int pmfs_dfs_insert_inodetree(struct super_block *sb,
	unsigned long pmfs_ino)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_blocknode *prev = NULL, *next = NULL;
	struct pmfs_blocknode *new_node;
	struct rb_root *tree = &sbi->inode_inuse_tree;
	int ret;

	ret = pmfs_find_free_slot(sbi, tree, pmfs_ino, pmfs_ino,
					&prev, &next);
	if (ret) {
		pmfs_dbg("%s: ino %lu already exists!: %d\n",
					__func__, pmfs_ino, ret);
		return ret;
	}

	if (prev && next && (pmfs_ino == prev->block_high + 1) &&
			(pmfs_ino + 1 == next->block_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		sbi->num_blocknode_inode--;
		prev->block_high = next->block_high;
		pmfs_free_inode_node(sb, next);
		goto finish;
	}
	if (prev && (pmfs_ino == prev->block_high + 1)) {
		/* Aligns left */
		prev->block_high++;
		goto finish;
	}
	if (next && (pmfs_ino + 1 == next->block_low)) {
		/* Aligns right */
		next->block_low--;
		goto finish;
	}

	/* Aligns somewhere in the middle */
	new_node = pmfs_alloc_inode_node(sb);
	PMFS_ASSERT(new_node);
	new_node->block_low = new_node->block_high = pmfs_ino;
	pmfs_insert_blocknode_inodetree(sbi, new_node);
	sbi->num_blocknode_inode++;

finish:
	return 0;
}

static void pmfs_init_blockmap_from_inode(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi = pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct free_list *free_list;
	struct pmfs_blocknode_lowhigh *entry;
	struct pmfs_blocknode *blknode;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	u64 curr_p;
	u64 cpuid;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		pmfs_dbg("%s: pi head is 0!\n", __func__);
		return;
	}

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			pmfs_dbg("%s: curr_p is NULL!\n", __func__);
			PMFS_ASSERT(0);
			break;
		}

		entry = (struct pmfs_blocknode_lowhigh *)pmfs_get_block(sb,
							curr_p);
		blknode = pmfs_alloc_blocknode(sb);
		if (blknode == NULL)
			PMFS_ASSERT(0);
		blknode->block_low = le64_to_cpu(entry->block_low);
		blknode->block_high = le64_to_cpu(entry->block_high);
		cpuid = get_cpuid(sbi, blknode->block_low);

		/* FIXME: Assume NR_CPUS not change */
		free_list = pmfs_get_free_list(sb, cpuid);
		pmfs_insert_blocknode_blocktree(sbi,
				&free_list->block_free_tree, blknode);
		free_list->num_blocknode++;
		if (free_list->num_blocknode == 1)
			free_list->first_node = blknode;
		free_list->num_free_blocks +=
			blknode->block_high - blknode->block_low + 1;
		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

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
		pmfs_insert_blocknode_inodetree(sbi, blknode);

		sbi->s_inodes_used_count +=
			blknode->block_high - blknode->block_low + 1;
		num_blocknode++;
		sbi->num_blocknode_inode++;
		if (!sbi->first_inode_blocknode)
			sbi->first_inode_blocknode = blknode;

		curr_p += sizeof(struct pmfs_blocknode_lowhigh);
	}

	pmfs_dbg("%s: %lu inode nodes\n", __func__, num_blocknode);
	pmfs_free_inode_log(sb, pi);
}

static bool pmfs_can_skip_full_scan(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	pmfs_init_blockmap_from_inode(sb);
	pmfs_init_inode_list_from_inode(sb);

	return true;
}

static u64 pmfs_append_blocknode_entry(struct super_block *sb,
	struct pmfs_blocknode *curr, u64 tail)
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
	entry->block_low = cpu_to_le64(curr->block_low);
	entry->block_high = cpu_to_le64(curr->block_high);
	pmfs_dbg_verbose("append entry block low %lu, high %lu\n",
			curr->block_low, curr->block_high);

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
		if (curr_p == 0) {
			pmfs_dbg("%s: failed to extend log\n", __func__);
			goto out;
		}
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct pmfs_alive_inode_entry *)pmfs_get_block(sb, curr_p);
	if (sih->ino != pi->pmfs_ino)
		pmfs_dbg("%s: inode number not match! sih %llu, pi %llu\n",
			__func__, sih->ino, pi->pmfs_ino);
	entry->pi_addr = sih->pi_addr;
	pmfs_dbg_verbose("append entry alive inode %llu, pmfs inode 0x%llx "
			"@ 0x%llx\n",
			sih->ino, sih->pi_addr, curr_p);

	pmfs_flush_buffer(entry, sizeof(struct pmfs_alive_inode_entry), 0);
	/* flush at the end */
	inode_table->log_tail = curr_p + size;
out:
	PMFS_END_TIMING(append_entry_t, append_time);
	alive_inode++;
	return curr_p;
}

static u64 pmfs_save_blocknode_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail)
{
	struct pmfs_blocknode *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct pmfs_blocknode_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct pmfs_blocknode, node);
		curr_entry = pmfs_append_blocknode_entry(sb, curr, temp_tail);
		temp_tail = curr_entry + size;
		temp = rb_next(temp);
		pmfs_free_blocknode(sb, curr);
	}

	return temp_tail;
}

static u64 pmfs_save_free_list_blocknodes(struct super_block *sb, int cpu,
	u64 temp_tail)
{
	struct free_list *free_list;

	free_list = pmfs_get_free_list(sb, cpu);
	temp_tail = pmfs_save_blocknode_to_log(sb, &free_list->block_free_tree,
								temp_tail);
	return temp_tail;
}

void pmfs_save_inode_list_to_log(struct super_block *sb)
{
	unsigned long num_blocks;
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_INODELIST_INO);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	int step = 0;
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

	temp_tail = pmfs_save_blocknode_to_log(sb, &sbi->inode_inuse_tree,
								new_block);
	pmfs_update_tail(pi, temp_tail);

	pmfs_dbg("%s: %lu inode nodes, step %d, pi head 0x%llx, tail 0x%llx\n",
		__func__, sbi->num_blocknode_inode, step, pi->log_head,
		pi->log_tail);
}

void pmfs_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct pmfs_inode *pi =  pmfs_get_inode_by_ino(sb, PMFS_BLOCKNODE_INO);
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_super_block *super;
	struct free_list *free_list;
	unsigned long num_blocknode = 0;
	unsigned long num_pages;
	int step = 0;
	int allocated;
	u64 new_block = 0;
	u64 temp_tail;
	int i;

	/* Allocate log pages before save blocknode mappings */
	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
	}

	free_list = pmfs_get_free_list(sb, SHARED_CPU);
	num_blocknode += free_list->num_blocknode;

	num_pages = num_blocknode / BLOCKNODE_PER_PAGE;
	if (num_blocknode % BLOCKNODE_PER_PAGE)
		num_pages++;

	allocated = pmfs_allocate_inode_log_pages(sb, pi, num_pages,
						&new_block);
	if (allocated != num_pages) {
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

	pmfs_memlock_range(sb, &super->s_wtime, PMFS_FAST_MOUNT_FIELD_SIZE);
	pmfs_flush_buffer(super, PMFS_SB_SIZE, 1);

	/* Finally update log head and tail */
	pi->log_head = new_block;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		temp_tail = pmfs_save_free_list_blocknodes(sb, i, temp_tail);
	}

	temp_tail = pmfs_save_free_list_blocknodes(sb, SHARED_CPU, temp_tail);
	pmfs_update_tail(pi, temp_tail);

	pmfs_dbg("%s: %lu blocknodes, %lu log pages, step %d, pi head 0x%llx, "
		"tail 0x%llx\n", __func__, num_blocknode, num_pages,
		step, pi->log_head, pi->log_tail);
}

static int pmfs_alloc_insert_blocknode_map(struct super_block *sb,
	int cpuid, unsigned long low, unsigned long high)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	struct rb_root *tree;
	struct pmfs_blocknode *blknode = NULL;
	unsigned long num_blocks = 0;

	num_blocks = high - low + 1;
	pmfs_dbgv("%s: cpu %d, low %lu, high %lu, num %lu\n",
		__func__, cpuid, low, high, num_blocks);
	free_list = pmfs_get_free_list(sb, cpuid);
	tree = &(free_list->block_free_tree);

	blknode = pmfs_alloc_blocknode(sb);
	if (blknode == NULL)
		return -ENOMEM;
	blknode->block_low = low;
	blknode->block_high = high;
	pmfs_insert_blocknode_blocktree(sbi, tree, blknode);
	if (!free_list->first_node)
		free_list->first_node = blknode;
	free_list->num_blocknode++;
	free_list->num_free_blocks += num_blocks;

	return 0;
}

static int __pmfs_build_blocknode_map(struct super_block *sb,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	unsigned long next = 0;
	unsigned long low = 0;
	unsigned long start, end;
	int cpuid = 0;

	free_list = pmfs_get_free_list(sb, cpuid);
	start = free_list->block_start;
	end = free_list->block_end + 1;
	while (1) {
		next = find_next_zero_bit(bitmap, end, start);
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				cpuid = SHARED_CPU;
			else
				cpuid++;
			free_list = pmfs_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
			continue;
		}

		low = next;
		next = find_next_bit(bitmap, end, next);
		if (pmfs_alloc_insert_blocknode_map(sb, cpuid,
				low << scale , (next << scale) - 1)) {
			pmfs_dbg("Error: could not insert %lu - %lu\n",
				low << scale, ((next << scale) - 1));
		}
		start = next;
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				cpuid = SHARED_CPU;
			else
				cpuid++;
			free_list = pmfs_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
		}
	}
	return 0;
}

static void pmfs_update_4K_map(struct super_block *sb,
	struct scan_bitmap *bm,	unsigned long *bitmap,
	unsigned long bsize, unsigned long scale)
{
	unsigned long next = 0;
	unsigned long low = 0;
	int i;

	while (1) {
		next = find_next_bit(bitmap, bsize, next);
		if (next == bsize)
			break;
		low = next;
		next = find_next_zero_bit(bitmap, bsize, next);
		for (i = (low << scale); i < (next << scale); i++)
			set_bm(i, bm, BM_4K);
		if (next == bsize)
			break;
	}
}

static void pmfs_build_blocknode_map(struct super_block *sb,
	struct scan_bitmap *bm)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	unsigned long num_used_block;
	int i;

	/*
	 * We are using free lists. Set 2M and 1G blocks in 4K map,
	 * and use 4K map to rebuild block map.
	 */
	pmfs_update_4K_map(sb, bm, bm->scan_bm_2M.bitmap,
		bm->scan_bm_2M.bitmap_size * 8, PAGE_SHIFT_2M - 12);
	pmfs_update_4K_map(sb, bm, bm->scan_bm_1G.bitmap,
		bm->scan_bm_1G.bitmap_size * 8, PAGE_SHIFT_1G - 12);

	/* Set initial used pages */
	num_used_block = sbi->reserved_blocks;
	for (i = 0; i < num_used_block; i++)
		set_bm(i, bm, BM_4K);

	__pmfs_build_blocknode_map(sb, bm->scan_bm_4K.bitmap,
			bm->scan_bm_4K.bitmap_size * 8, PAGE_SHIFT - 12);
}

void pmfs_print_bmentry_tree(struct single_scan_bm *scan_bm,
	enum bm_type type)
{
	struct multi_set_entry *entry;
	struct rb_node *temp;

	temp = rb_first(&scan_bm->multi_set_tree);
	while (temp) {
		entry = container_of(temp, struct multi_set_entry, node);
		pmfs_dbg("%s: type %d: entry bit low %lu, bit high %lu, "
			"refcount %d\n", __func__, type, entry->bit_low,
			entry->bit_high, entry->refcount);
		temp = rb_next(temp);
	}

	return;
}

static void pmfs_check_bmentry(struct single_scan_bm *scan_bm,
	enum bm_type type)
{
	if (scan_bm->num_entries)
		pmfs_dbg("%s: bm type %d: still has %d entries?\n",
			__func__, type, scan_bm->num_entries);

	pmfs_print_bmentry_tree(scan_bm, type);
}

static void free_bm(struct scan_bitmap *bm)
{
	kfree(bm->scan_bm_4K.bitmap);
	kfree(bm->scan_bm_2M.bitmap);
	kfree(bm->scan_bm_1G.bitmap);
	pmfs_check_bmentry(&bm->scan_bm_4K, BM_4K);
	pmfs_check_bmentry(&bm->scan_bm_2M, BM_2M);
	pmfs_check_bmentry(&bm->scan_bm_1G, BM_1G);
	kfree(bm);
	destroy_bmentry_cache();
}

static struct scan_bitmap *alloc_bm(unsigned long initsize)
{
	struct scan_bitmap *bm;

	bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
	if (!bm)
		return NULL;

	bm->scan_bm_4K.bitmap_size = (initsize >> (PAGE_SHIFT + 0x3));
	bm->scan_bm_2M.bitmap_size = (initsize >> (PAGE_SHIFT_2M + 0x3));
	bm->scan_bm_1G.bitmap_size = (initsize >> (PAGE_SHIFT_1G + 0x3));

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

	bm->scan_bm_4K.multi_set_tree = RB_ROOT;
	bm->scan_bm_2M.multi_set_tree = RB_ROOT;
	bm->scan_bm_1G.multi_set_tree = RB_ROOT;

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
	pmfs_dbg("%s: freed %u, alive inode %lu\n",
				__func__, freed, alive_inode);
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
		sih->ino = ino;
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
	if (bm) {
		pi->i_blocks = 0;
		if (pmfs_ino >= PMFS_NORMAL_INODE_START) {
			pmfs_dfs_insert_inodetree(sb, pmfs_ino);
		}
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

	sbi->s_inodes_used_count = 0;

	/* Initialize inuse inode list */
	if (pmfs_init_inode_table(sb) < 0)
		return -EINVAL;

	/* Handle special inodes */
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

int pmfs_inode_log_recovery(struct super_block *sb, int multithread)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_super_block *super = pmfs_get_super(sb);
	unsigned long initsize = le64_to_cpu(super->s_size);
	struct scan_bitmap *bm = NULL;
	bool value = false;
	int ret;
	timing_t recovery_time;

	PMFS_START_TIMING(recovery_t, recovery_time);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);

	/* initialize free list info */
	pmfs_init_blockmap(sb, 1);

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
		pmfs_build_blocknode_map(sb, bm);
		free_bm(bm);
	}

	PMFS_END_TIMING(recovery_t, recovery_time);
	return ret;
}
