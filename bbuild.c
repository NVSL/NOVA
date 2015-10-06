/*
 * NOVA Recovery routines.
 *
 * Copyright 2015 NVSL, UC San Diego
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
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
#include "nova.h"

static unsigned long alive_inode;
static struct kmem_cache *nova_bmentry_cachep;

static int __init init_bmentry_cache(void)
{
	nova_bmentry_cachep = kmem_cache_create("nova_bmentry_cache",
					       sizeof(struct multi_set_entry),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), NULL);
	if (nova_bmentry_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_bmentry_cache(void)
{
	kmem_cache_destroy(nova_bmentry_cachep);
}

inline int nova_rbtree_compare_bmentry(struct multi_set_entry *curr,
	unsigned long bit)
{
	if (bit < curr->bit_low)
		return -1;
	if (bit > curr->bit_high)
		return 1;

	return 0;
}

static int nova_find_bmentry(struct single_scan_bm *scan_bm,
	unsigned long bit, struct multi_set_entry **entry)
{
	struct multi_set_entry *curr;
	struct rb_node *temp;
	int compVal;

	temp = scan_bm->multi_set_tree.rb_node;

	while (temp) {
		curr = container_of(temp, struct multi_set_entry, node);
		compVal = nova_rbtree_compare_bmentry(curr, bit);

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

static int nova_insert_bmentry(struct single_scan_bm *scan_bm,
	struct multi_set_entry *entry)
{
	struct multi_set_entry *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(scan_bm->multi_set_tree.rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct multi_set_entry, node);
		compVal = nova_rbtree_compare_bmentry(curr, entry->bit_low);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			nova_dbg("%s: entry %lu - %lu already exists\n",
				__func__, entry->bit_low, entry->bit_high);
			return -EINVAL;
		}
	}

	rb_link_node(&entry->node, parent, temp);
	rb_insert_color(&entry->node, &scan_bm->multi_set_tree);
	scan_bm->num_entries++;
	return 0;
}

static void nova_try_merge_bmentry(struct single_scan_bm *scan_bm,
	struct multi_set_entry *curr_entry)
{
	struct rb_node *prev, *next;
	struct multi_set_entry *prev_entry, *next_entry;

	prev = rb_prev(&curr_entry->node);
	if (prev) {
		prev_entry = rb_entry(prev, struct multi_set_entry, node);
		if (prev_entry->bit_high >= curr_entry->bit_low) {
			nova_dbg("%s: ERROR: entry overlap: prev low %lu, "
				"high %lu, curr low %lu, high %lu\n", __func__,
				prev_entry->bit_low, prev_entry->bit_high,
				curr_entry->bit_low, curr_entry->bit_high);
			return;
		}
		if (prev_entry->bit_high + 1 == curr_entry->bit_low &&
				prev_entry->refcount == curr_entry->refcount) {
			rb_erase(&curr_entry->node, &scan_bm->multi_set_tree);
			prev_entry->bit_high = curr_entry->bit_high;
			kmem_cache_free(nova_bmentry_cachep, curr_entry);
			curr_entry = prev_entry;
			scan_bm->num_entries--;
		}
	}

	next = rb_next(&curr_entry->node);
	if (next) {
		next_entry = rb_entry(next, struct multi_set_entry, node);
		if (curr_entry->bit_high >= next_entry->bit_low) {
			nova_dbg("%s: ERROR: entry overlap: curr low %lu, "
				"high %lu, next low %lu, high %lu\n", __func__,
				curr_entry->bit_low, curr_entry->bit_high,
				next_entry->bit_low, next_entry->bit_high);
			return;
		}
		if (curr_entry->bit_high + 1 == next_entry->bit_low &&
				curr_entry->refcount == next_entry->refcount) {
			rb_erase(&next_entry->node, &scan_bm->multi_set_tree);
			curr_entry->bit_high = next_entry->bit_high;
			kmem_cache_free(nova_bmentry_cachep, next_entry);
			scan_bm->num_entries--;
		}
	}
}

static void nova_insert_bit_range_to_tree(struct single_scan_bm *scan_bm,
	unsigned long bit_low, unsigned long bit_high, int refcount,
	int try_merge)
{
	struct multi_set_entry *entry;

	if (bit_low > bit_high || refcount < 2) {
		nova_dbg("%s: insert invalid range: low %lu, high %lu, "
			"refcount %d\n", __func__, bit_low, bit_high,
			refcount);
		return;
	}

	entry = kmem_cache_alloc(nova_bmentry_cachep, GFP_NOFS);
	if (!entry)
		NOVA_ASSERT(0);

	entry->bit_low = bit_low;
	entry->bit_high = bit_high;
	entry->refcount = refcount;
	nova_insert_bmentry(scan_bm, entry);
	if (try_merge)
		nova_try_merge_bmentry(scan_bm, entry);
}

static void nova_inc_bit_in_bmentry(struct single_scan_bm *scan_bm,
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
		nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 1);
		return;
	}

	/* Align to right */
	if (bit == entry->bit_high) {
		entry->bit_high--;
		nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 1);
		return;
	}

	/* In the middle. Break the entry and insert new ones */
	new_bit_low = bit + 1;
	new_bit_high = entry->bit_high;
	entry->bit_high = bit - 1;

	nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount + 1, 0);

	nova_insert_bit_range_to_tree(scan_bm, new_bit_low, new_bit_high,
					entry->refcount, 0);
}

static void set_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry;
	int found = 0;

	if (test_and_set_bit(bit, scan_bm->bitmap) == 0)
		return;

	nova_dbgv("%s: type %d, bit %lu exists\n", __func__, type, bit);

	if (scan_bm->num_entries) {
		found = nova_find_bmentry(scan_bm, bit, &entry);
		if (found == 1) {
			nova_inc_bit_in_bmentry(scan_bm, bit, entry);
			return;
		}
	}

	nova_insert_bit_range_to_tree(scan_bm, bit, bit, 2, 1);
}

static void nova_dec_bit_in_bmentry(struct single_scan_bm *scan_bm,
	unsigned long bit, struct multi_set_entry *entry)
{
	unsigned long new_bit_low, new_bit_high;

	/* Single bit entry */
	if (bit == entry->bit_low && bit == entry->bit_high) {
		entry->refcount--;
		if (entry->refcount == 1) {
			rb_erase(&entry->node, &scan_bm->multi_set_tree);
			kmem_cache_free(nova_bmentry_cachep, entry);
			scan_bm->num_entries--;
		}
		return;
	}

	/* Align to left */
	if (bit == entry->bit_low) {
		entry->bit_low++;
		if (entry->refcount == 2)
			return;
		nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 1);
		return;
	}

	/* Align to right */
	if (bit == entry->bit_high) {
		entry->bit_high--;
		if (entry->refcount == 2)
			return;
		nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 1);
		return;
	}

	/* In the middle. Break the entry and insert new ones */
	new_bit_low = bit + 1;
	new_bit_high = entry->bit_high;
	entry->bit_high = bit - 1;

	if (entry->refcount > 2)
		nova_insert_bit_range_to_tree(scan_bm, bit, bit,
					entry->refcount - 1, 0);

	nova_insert_bit_range_to_tree(scan_bm, new_bit_low, new_bit_high,
					entry->refcount, 0);
}

static void clear_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm, enum bm_type type)
{
	struct multi_set_entry *entry;
	int found = 0;

	if (scan_bm->num_entries) {
		found = nova_find_bmentry(scan_bm, bit, &entry);
		if (found == 1) {
			nova_dec_bit_in_bmentry(scan_bm, bit, entry);
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

static int get_cpuid(struct nova_sb_info *sbi, unsigned long blocknr)
{
	int cpuid;

	cpuid = blocknr / sbi->per_list_blocks;

	if (cpuid >= sbi->cpus)
		cpuid = SHARED_CPU;

	return cpuid;
}

static int nova_dfs_insert_inodetree(struct super_block *sb,
	unsigned long nova_ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *prev = NULL, *next = NULL;
	struct nova_range_node *new_node;
	struct rb_root *tree = &sbi->inode_inuse_tree;
	int ret;

	ret = nova_find_free_slot(sbi, tree, nova_ino, nova_ino,
					&prev, &next);
	if (ret) {
		nova_dbg("%s: ino %lu already exists!: %d\n",
					__func__, nova_ino, ret);
		return ret;
	}

	if (prev && next && (nova_ino == prev->range_high + 1) &&
			(nova_ino + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		sbi->num_range_node_inode--;
		prev->range_high = next->range_high;
		nova_free_inode_node(sb, next);
		goto finish;
	}
	if (prev && (nova_ino == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high++;
		goto finish;
	}
	if (next && (nova_ino + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low--;
		goto finish;
	}

	/* Aligns somewhere in the middle */
	new_node = nova_alloc_inode_node(sb);
	NOVA_ASSERT(new_node);
	new_node->range_low = new_node->range_high = nova_ino;
	nova_insert_inodetree(sbi, new_node);
	sbi->num_range_node_inode++;

finish:
	return 0;
}

static void nova_init_blockmap_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct free_list *free_list;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *blknode;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_p;
	u64 cpuid;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return;
	}

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
			break;
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		blknode = nova_alloc_blocknode(sb);
		if (blknode == NULL)
			NOVA_ASSERT(0);
		blknode->range_low = le64_to_cpu(entry->range_low);
		blknode->range_high = le64_to_cpu(entry->range_high);
		cpuid = get_cpuid(sbi, blknode->range_low);

		/* FIXME: Assume NR_CPUS not change */
		free_list = nova_get_free_list(sb, cpuid);
		nova_insert_blocktree(sbi,
				&free_list->block_free_tree, blknode);
		free_list->num_blocknode++;
		if (free_list->num_blocknode == 1)
			free_list->first_node = blknode;
		free_list->num_free_blocks +=
			blknode->range_high - blknode->range_low + 1;
		curr_p += sizeof(struct nova_range_node_lowhigh);
	}

	nova_free_inode_log(sb, pi);
}

static void nova_init_inode_list_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *range_node;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	unsigned long num_inode_node = 0;
	u64 curr_p;

	sbi->num_range_node_inode = 0;
	curr_p = pi->log_head;
	if (curr_p == 0)
		nova_dbg("%s: pi head is 0!\n", __func__);

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size, 0)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			NOVA_ASSERT(0);
		range_node->range_low = entry->range_low;
		range_node->range_high = entry->range_high;
		nova_insert_inodetree(sbi, range_node);

		sbi->s_inodes_used_count +=
			range_node->range_high - range_node->range_low + 1;
		num_inode_node++;
		sbi->num_range_node_inode++;
		if (!sbi->first_inode_range)
			sbi->first_inode_range = range_node;

		curr_p += sizeof(struct nova_range_node_lowhigh);
	}

	nova_dbg("%s: %lu inode nodes\n", __func__, num_inode_node);
	nova_free_inode_log(sb, pi);
}

static bool nova_can_skip_full_scan(struct super_block *sb)
{
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	nova_init_blockmap_from_inode(sb);
	nova_init_inode_list_from_inode(sb);

	return true;
}

static u64 nova_append_range_node_entry(struct super_block *sb,
	struct nova_range_node *curr, u64 tail)
{
	u64 curr_p;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	struct nova_range_node_lowhigh *entry;
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);

	curr_p = tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, 0) &&
				next_log_page(sb, curr_p) == 0)) {
		nova_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_range_node_lowhigh *)nova_get_block(sb, curr_p);
	entry->range_low = cpu_to_le64(curr->range_low);
	entry->range_high = cpu_to_le64(curr->range_high);
	nova_dbg_verbose("append entry block low %lu, high %lu\n",
			curr->range_low, curr->range_high);

	nova_flush_buffer(entry, sizeof(struct nova_range_node_lowhigh), 0);
out:
	NOVA_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

static u64 nova_append_alive_inode_entry(struct super_block *sb,
	struct nova_inode *inode_table, struct nova_inode *pi,
	struct nova_inode_info_header *sih,
	struct nova_inode_info_header *inode_table_sih)
{
	size_t size = sizeof(struct nova_alive_inode_entry);
	struct nova_alive_inode_entry *entry;
	u64 curr_p;
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);

	curr_p = inode_table->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size, 0) &&
				next_log_page(sb, curr_p) == 0)) {
		curr_p = nova_extend_inode_log(sb, inode_table,
						inode_table_sih, curr_p, 0);
		if (curr_p == 0) {
			nova_dbg("%s: failed to extend log\n", __func__);
			goto out;
		}
	}

	if (is_last_entry(curr_p, size, 0))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_alive_inode_entry *)nova_get_block(sb, curr_p);
	if (sih->ino != pi->nova_ino)
		nova_dbg("%s: inode number not match! sih %lu, pi %llu\n",
			__func__, sih->ino, pi->nova_ino);
	entry->pi_addr = sih->pi_addr;
	nova_dbg_verbose("append entry alive inode %lu, nova inode 0x%lx "
			"@ 0x%llx\n",
			sih->ino, sih->pi_addr, curr_p);

	nova_flush_buffer(entry, sizeof(struct nova_alive_inode_entry), 0);
	/* flush at the end */
	inode_table->log_tail = curr_p + size;
out:
	NOVA_END_TIMING(append_entry_t, append_time);
	alive_inode++;
	return curr_p;
}

static u64 nova_save_range_nodes_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail)
{
	struct nova_range_node *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		curr_entry = nova_append_range_node_entry(sb, curr, temp_tail);
		temp_tail = curr_entry + size;
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}

	return temp_tail;
}

static u64 nova_save_free_list_blocknodes(struct super_block *sb, int cpu,
	u64 temp_tail)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	temp_tail = nova_save_range_nodes_to_log(sb, &free_list->block_free_tree,
								temp_tail);
	return temp_tail;
}

void nova_save_inode_list_to_log(struct super_block *sb)
{
	unsigned long num_blocks;
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int step = 0;
	u64 temp_tail;
	u64 new_block;
	int allocated;

	num_blocks = sbi->num_range_node_inode / RANGENODE_PER_PAGE;
	if (sbi->num_range_node_inode % RANGENODE_PER_PAGE)
		num_blocks++;

	allocated = nova_allocate_inode_log_pages(sb, pi, num_blocks,
						&new_block);
	if (allocated != num_blocks) {
		nova_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	pi->log_head = new_block;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	temp_tail = nova_save_range_nodes_to_log(sb, &sbi->inode_inuse_tree,
								new_block);
	nova_update_tail(pi, temp_tail);

	nova_dbg("%s: %lu inode nodes, step %d, pi head 0x%llx, tail 0x%llx\n",
		__func__, sbi->num_range_node_inode, step, pi->log_head,
		pi->log_tail);
}

void nova_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super;
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
		free_list = nova_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
	}

	free_list = nova_get_free_list(sb, SHARED_CPU);
	num_blocknode += free_list->num_blocknode;

	num_pages = num_blocknode / RANGENODE_PER_PAGE;
	if (num_blocknode % RANGENODE_PER_PAGE)
		num_pages++;

	allocated = nova_allocate_inode_log_pages(sb, pi, num_pages,
						&new_block);
	if (allocated != num_pages) {
		nova_dbg("Error saving blocknode mappings: %d\n", allocated);
		return;
	}

	/*
	 * save the total allocated blocknode mappings
	 * in super block
	 * No transaction is needed as we will recover the fields
	 * via DFS recovery
	 */
	super = nova_get_super(sb);

	nova_memunlock_range(sb, &super->s_wtime, NOVA_FAST_MOUNT_FIELD_SIZE);

	super->s_wtime = cpu_to_le32(get_seconds());

	nova_memlock_range(sb, &super->s_wtime, NOVA_FAST_MOUNT_FIELD_SIZE);
	nova_flush_buffer(super, NOVA_SB_SIZE, 1);

	/* Finally update log head and tail */
	pi->log_head = new_block;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		temp_tail = nova_save_free_list_blocknodes(sb, i, temp_tail);
	}

	temp_tail = nova_save_free_list_blocknodes(sb, SHARED_CPU, temp_tail);
	nova_update_tail(pi, temp_tail);

	nova_dbg("%s: %lu blocknodes, %lu log pages, step %d, pi head 0x%llx, "
		"tail 0x%llx\n", __func__, num_blocknode, num_pages,
		step, pi->log_head, pi->log_tail);
}

static int nova_insert_blocknode_map(struct super_block *sb,
	int cpuid, unsigned long low, unsigned long high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	struct rb_root *tree;
	struct nova_range_node *blknode = NULL;
	unsigned long num_blocks = 0;

	num_blocks = high - low + 1;
	nova_dbgv("%s: cpu %d, low %lu, high %lu, num %lu\n",
		__func__, cpuid, low, high, num_blocks);
	free_list = nova_get_free_list(sb, cpuid);
	tree = &(free_list->block_free_tree);

	blknode = nova_alloc_blocknode(sb);
	if (blknode == NULL)
		return -ENOMEM;
	blknode->range_low = low;
	blknode->range_high = high;
	nova_insert_blocktree(sbi, tree, blknode);
	if (!free_list->first_node)
		free_list->first_node = blknode;
	free_list->num_blocknode++;
	free_list->num_free_blocks += num_blocks;

	return 0;
}

static int __nova_build_blocknode_map(struct super_block *sb,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long next = 0;
	unsigned long low = 0;
	unsigned long start, end;
	int cpuid = 0;

	free_list = nova_get_free_list(sb, cpuid);
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
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
			continue;
		}

		low = next;
		next = find_next_bit(bitmap, end, next);
		if (nova_insert_blocknode_map(sb, cpuid,
				low << scale , (next << scale) - 1)) {
			nova_dbg("Error: could not insert %lu - %lu\n",
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
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
		}
	}
	return 0;
}

static void nova_update_4K_map(struct super_block *sb,
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

static void nova_build_blocknode_map(struct super_block *sb,
	struct scan_bitmap *bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long num_used_block;
	int i;

	/*
	 * We are using free lists. Set 2M and 1G blocks in 4K map,
	 * and use 4K map to rebuild block map.
	 */
	nova_update_4K_map(sb, bm, bm->scan_bm_2M.bitmap,
		bm->scan_bm_2M.bitmap_size * 8, PAGE_SHIFT_2M - 12);
	nova_update_4K_map(sb, bm, bm->scan_bm_1G.bitmap,
		bm->scan_bm_1G.bitmap_size * 8, PAGE_SHIFT_1G - 12);

	/* Set initial used pages */
	num_used_block = sbi->reserved_blocks;
	for (i = 0; i < num_used_block; i++)
		set_bm(i, bm, BM_4K);

	__nova_build_blocknode_map(sb, bm->scan_bm_4K.bitmap,
			bm->scan_bm_4K.bitmap_size * 8, PAGE_SHIFT - 12);
}

void nova_print_bmentry_tree(struct single_scan_bm *scan_bm,
	enum bm_type type)
{
	struct multi_set_entry *entry;
	struct rb_node *temp;

	temp = rb_first(&scan_bm->multi_set_tree);
	while (temp) {
		entry = container_of(temp, struct multi_set_entry, node);
		nova_dbg("%s: type %d: entry bit low %lu, bit high %lu, "
			"refcount %d\n", __func__, type, entry->bit_low,
			entry->bit_high, entry->refcount);
		temp = rb_next(temp);
	}

	return;
}

static void nova_check_bmentry(struct single_scan_bm *scan_bm,
	enum bm_type type)
{
	if (scan_bm->num_entries)
		nova_dbg("%s: bm type %d: still has %d entries?\n",
			__func__, type, scan_bm->num_entries);

	nova_print_bmentry_tree(scan_bm, type);
}

static void free_bm(struct scan_bitmap *bm)
{
	kfree(bm->scan_bm_4K.bitmap);
	kfree(bm->scan_bm_2M.bitmap);
	kfree(bm->scan_bm_1G.bitmap);
	nova_check_bmentry(&bm->scan_bm_4K, BM_4K);
	nova_check_bmentry(&bm->scan_bm_2M, BM_2M);
	nova_check_bmentry(&bm->scan_bm_1G, BM_1G);
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

struct kmem_cache *nova_header_cachep;

struct nova_inode_info_header *nova_alloc_header(struct super_block *sb,
	u16 i_mode)
{
	struct nova_inode_info_header *p;
	p = (struct nova_inode_info_header *)
		kmem_cache_alloc(nova_header_cachep, GFP_NOFS);

	if (!p)
		NOVA_ASSERT(0);

	p->log_pages = 0;
	p->mmap_pages = 0;
	p->i_size = 0;
	p->pi_addr = 0;
	INIT_RADIX_TREE(&p->tree, GFP_ATOMIC);
	INIT_RADIX_TREE(&p->cache_tree, GFP_ATOMIC);
	p->i_mode = i_mode;

	atomic64_inc(&header_alloc);
	return p;
}

static void nova_free_header(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	kmem_cache_free(nova_header_cachep, sih);
	atomic64_inc(&header_free);
}

static int nova_inode_alive(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_inode **return_pi)
{
	struct nova_inode *pi;

	if (sih->ino && sih->pi_addr) {
		pi = (struct nova_inode *)nova_get_block(sb, sih->pi_addr);
		if (pi->valid) {
			*return_pi = pi;
			return 1;
		}
	}

	return 0;
}

unsigned int nova_free_header_tree(struct super_block *sb)
{
	struct nova_inode *inode_table = nova_get_inode_table(sb);
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header *sih, *inode_table_sih;
	struct nova_inode_info_header *sih_array[FREE_BATCH];
	unsigned long ino = 0;
	int nr_sih;
	struct nova_inode *pi = NULL;
	unsigned int freed = 0;
	int i;
	void *ret;

	inode_table_sih = nova_alloc_header(sb, 0);

	do {
		nr_sih = radix_tree_gang_lookup(&sbi->header_tree,
				(void **)sih_array, ino, FREE_BATCH);
		for (i = 0; i < nr_sih; i++) {
			sih = sih_array[i];
			BUG_ON(!sih);
			ino = sih->ino;
			ret = radix_tree_delete(&sbi->header_tree, ino);
			BUG_ON(!ret || ret != sih);
			if (nova_inode_alive(sb, sih, &pi))
				nova_append_alive_inode_entry(sb,
						inode_table, pi, sih,
						inode_table_sih);
			nova_free_dram_resource(sb, sih);
			nova_free_header(sb, sih);
			freed++;
		}
		ino++;
	} while (nr_sih == FREE_BATCH);

	nova_free_header(sb, inode_table_sih);
	nova_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);
	nova_dbg("%s: freed %u, alive inode %lu\n",
				__func__, freed, alive_inode);
	return freed;
}

int nova_assign_info_header(struct super_block *sb, unsigned long ino,
	struct nova_inode_info_header **sih, u16 i_mode, int need_lock)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header *old_sih, *new_sih;
	int ret = 0;

	nova_dbgv("assign_header ino %lu\n", ino);

	if (need_lock)
		mutex_lock(&sbi->inode_table_mutex);

	old_sih = radix_tree_lookup(&sbi->header_tree, ino);
	if (old_sih) {
		old_sih->i_mode = i_mode;
		*sih = old_sih;
	} else {
		new_sih = nova_alloc_header(sb, i_mode);
		if (!new_sih) {
			ret = -ENOMEM;
			goto out;
		}
		ret = radix_tree_insert(&sbi->header_tree, ino, new_sih);
		if (ret) {
			nova_dbg("%s: ERROR %d\n", __func__, ret);
			goto out;
		}
		*sih = new_sih;
	}

	if (sih && *sih)
		(*sih)->ino = ino;
out:
	if (need_lock)
		mutex_unlock(&sbi->inode_table_mutex);

	return ret;
}

int nova_recover_inode(struct super_block *sb, u64 pi_addr,
	struct scan_bitmap *bm, int cpuid, int multithread)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header *sih;
	struct nova_inode *pi;
	unsigned long nova_ino;
	int need_lock = multithread;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	if (!pi)
		NOVA_ASSERT(0);

	if (pi->valid == 0)
		return 0;

	nova_ino = pi->nova_ino;
	if (bm) {
		pi->i_blocks = 0;
		if (nova_ino >= NOVA_NORMAL_INODE_START) {
			nova_dfs_insert_inodetree(sb, nova_ino);
		}
		sbi->s_inodes_used_count++;
	}

	nova_dbg_verbose("%s: inode %lu, addr 0x%llx, valid %d, "
			"head 0x%llx, tail 0x%llx\n",
			__func__, nova_ino, pi_addr, pi->valid,
			pi->log_head, pi->log_tail);

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		nova_dbg_verbose("This is thread %d, processing file %p, "
				"nova ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, nova_ino, pi->log_head,
				pi->log_tail);
		nova_assign_info_header(sb, nova_ino, &sih,
				__le16_to_cpu(pi->i_mode), need_lock);
		nova_rebuild_file_inode_tree(sb, pi, pi_addr, sih, bm);
		break;
	case S_IFDIR:
		nova_dbg_verbose("This is thread %d, processing dir %p, "
				"nova ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, nova_ino, pi->log_head,
				pi->log_tail);
		nova_assign_info_header(sb, nova_ino, &sih,
				__le16_to_cpu(pi->i_mode), need_lock);
		nova_rebuild_dir_inode_tree(sb, pi, pi_addr, sih, bm);
		break;
	case S_IFLNK:
		nova_dbg_verbose("This is thread %d, processing symlink %p, "
				"nova ino %lu, head 0x%llx, tail 0x%llx\n",
				cpuid, pi, nova_ino, pi->log_head,
				pi->log_tail);
		/* No need to rebuild tree for symlink files */
		nova_assign_info_header(sb, nova_ino, &sih,
				__le16_to_cpu(pi->i_mode), need_lock);
		sih->pi_addr = pi_addr;
		if (bm && pi->log_head) {
			BUG_ON(pi->log_head & (PAGE_SIZE - 1));
			set_bm(pi->log_head >> PAGE_SHIFT, bm, BM_4K);
		}
		break;
	default:
		break;
	}

	return 0;
}

/*********************** DFS recovery *************************/

int nova_dfs_recovery(struct super_block *sb, struct scan_bitmap *bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	u64 root_addr = NOVA_ROOT_INO_START;
	int ret;

	sbi->s_inodes_used_count = 0;

	/* Initialize inuse inode list */
	if (nova_init_inode_table(sb) < 0)
		return -EINVAL;

	/* Handle special inodes */
	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->log_head = pi->log_tail = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	pi = nova_get_inode_table(sb);
	pi->log_head = pi->log_tail = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	pi = nova_get_inode_by_ino(sb, NOVA_LITEJOURNAL_INO);
	if (pi->log_head)
		set_bm(pi->log_head >> PAGE_SHIFT, bm, BM_4K);

	PERSISTENT_BARRIER();
	/* Start from the root iode */
	ret = nova_recover_inode(sb, root_addr, bm, smp_processor_id(), 0);

	nova_dbg("DFS recovery total recovered %lu\n",
				sbi->s_inodes_used_count);
	return ret;
}

/*********************** Singlethread recovery *************************/

int *processed;

static void nova_inode_table_singlethread_crawl(struct super_block *sb,
	struct nova_inode *inode_table)
{
	struct nova_alive_inode_entry *entry = NULL;
	size_t size = sizeof(struct nova_alive_inode_entry);
	u64 curr_p = inode_table->log_head;

	nova_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, inode_table->log_tail);

	if (curr_p == 0 && inode_table->log_tail == 0)
		return;

	while (curr_p != inode_table->log_tail) {
		if (is_last_entry(curr_p, size, 0))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "Alive inode log reaches NULL!\n");
			NOVA_ASSERT(0);
		}

		entry = (struct nova_alive_inode_entry *)nova_get_block(sb,
								curr_p);

		nova_recover_inode(sb, entry->pi_addr, NULL,
						smp_processor_id(), 0);
		processed[smp_processor_id()]++;
		curr_p += size;
	}

	nova_free_inode_log(sb, inode_table);
	inode_table->log_head = inode_table->log_tail = 0;
	nova_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);

	return;
}

int nova_singlethread_recovery(struct super_block *sb)
{
	struct nova_inode *inode_table = nova_get_inode_table(sb);
	int cpus = num_online_cpus();
	int i, total = 0;
	int ret = 0;

	processed = kzalloc(cpus * sizeof(int), GFP_KERNEL);
	if (!processed)
		return -ENOMEM;

	nova_inode_table_singlethread_crawl(sb, inode_table);

	for (i = 0; i < cpus; i++) {
		total += processed[i];
		nova_dbg_verbose("CPU %d: recovered %d\n", i, processed[i]);
	}

	kfree(processed);
	nova_dbg("Singlethread total recovered %d\n", total);
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
	nova_dbg_verbose("Enqueue at %d\n", ring->enqueue);
	if (ring->tasks[ring->enqueue])
		nova_dbg("%s: ERROR existing entry %llu\n", __func__,
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
		NOVA_ASSERT(0);

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
			nova_recover_inode(sb, pi_addr, NULL,
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

static void nova_inode_table_multithread_crawl(struct super_block *sb,
	struct nova_inode *inode_table, int cpus)
{
	struct nova_alive_inode_entry *entry = NULL;
	size_t size = sizeof(struct nova_alive_inode_entry);
	struct task_ring *ring = NULL;
	u64 curr_p = inode_table->log_head;

	nova_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, inode_table->log_tail);

	if (curr_p == 0 && inode_table->log_tail == 0)
		return;

	while (curr_p != inode_table->log_tail) {
		if (is_last_entry(curr_p, size, 0))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "Alive inode log reaches NULL!\n");
			NOVA_ASSERT(0);
		}

		entry = (struct nova_alive_inode_entry *)nova_get_block(sb,
								curr_p);

		while ((ring = get_free_ring(cpus, ring)) == NULL) {
			wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
		}

		task_ring_enqueue(ring, entry->pi_addr);
		wake_up_interruptible(&ring->assign_wq);

		curr_p += size;
	}

	nova_free_inode_log(sb, inode_table);
	inode_table->log_head = inode_table->log_tail = 0;
	nova_flush_buffer(&inode_table->log_head, CACHELINE_SIZE, 1);

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
		nova_dbg_verbose("Ring %d recovered %d\n", i, ring->processed);
		total += ring->processed;
	}

	nova_dbg("Multithread total recovered %d\n", total);
}

int nova_multithread_recovery(struct super_block *sb)
{
	struct nova_inode *inode_table = nova_get_inode_table(sb);
	int cpus;
	int ret;

	cpus = num_online_cpus();
	nova_dbg("%s: %d cpus\n", __func__, cpus);

	ret = allocate_resources(sb, cpus);
	if (ret)
		return ret;

	nova_inode_table_multithread_crawl(sb, inode_table, cpus);

	wait_to_finish(cpus);
	free_resources();
	return ret;
}

/*********************** Recovery entrance *************************/

int nova_inode_log_recovery(struct super_block *sb, int multithread)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = nova_get_super(sb);
	unsigned long initsize = le64_to_cpu(super->s_size);
	struct scan_bitmap *bm = NULL;
	bool value = false;
	int ret;
	timing_t start, end;

	/* Always check recovery time */
	if (measure_timing == 0)
		getrawmonotonic(&start);

	NOVA_START_TIMING(recovery_t, start);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(initsize) >> PAGE_SHIFT);

	/* initialize free list info */
	nova_init_blockmap(sb, 1);

	value = nova_can_skip_full_scan(sb);
	if (value) {
		nova_dbg("NOVA: Skipping build blocknode map\n");
	} else {
		nova_dbg("NOVA: build blocknode map\n");
		bm = alloc_bm(initsize);
		if (!bm)
			return -ENOMEM;
	}

	nova_dbgv("%s\n", __func__);

	if (bm) {
		sbi->s_inodes_used_count = 0;
		ret = nova_dfs_recovery(sb, bm);
	} else {
		if (multithread)
			ret = nova_multithread_recovery(sb);
		else
			ret = nova_singlethread_recovery(sb);
	}

	if (bm) {
		nova_build_blocknode_map(sb, bm);
		free_bm(bm);
	}

	NOVA_END_TIMING(recovery_t, start);
	if (measure_timing == 0) {
		getrawmonotonic(&end);
		Timingstats[recovery_t] +=
			(end.tv_sec - start.tv_sec) * 1000000000 +
			(end.tv_nsec - start.tv_nsec);
	}

	return ret;
}
