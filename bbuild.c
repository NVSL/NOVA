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

static inline void set_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm)
{
	set_bit(bit, scan_bm->bitmap);
}

inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type)
{
	switch (type) {
		case BM_4K:
			set_scan_bm(bit, &bm->scan_bm_4K);
			break;
		case BM_2M:
			set_scan_bm(bit, &bm->scan_bm_2M);
			break;
		case BM_1G:
			set_scan_bm(bit, &bm->scan_bm_1G);
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
	struct header_tree *header_tree;
	struct nova_range_node *prev = NULL, *next = NULL;
	struct nova_range_node *new_node;
	unsigned long internal_ino;
	int cpu;
	struct rb_root *tree;
	int ret;

	cpu = nova_ino % sbi->cpus;
	internal_ino = nova_ino / sbi->cpus;
	header_tree = &sbi->header_trees[cpu];
	tree = &header_tree->inode_inuse_tree;

	ret = nova_find_free_slot(sbi, tree, internal_ino, internal_ino,
					&prev, &next);
	if (ret) {
		nova_dbg("%s: ino %lu already exists!: %d\n",
					__func__, nova_ino, ret);
		return ret;
	}

	if (prev && next && (internal_ino == prev->range_high + 1) &&
			(internal_ino + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		header_tree->num_range_node_inode--;
		prev->range_high = next->range_high;
		nova_free_inode_node(sb, next);
		goto finish;
	}
	if (prev && (internal_ino == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high++;
		goto finish;
	}
	if (next && (internal_ino + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low--;
		goto finish;
	}

	/* Aligns somewhere in the middle */
	new_node = nova_alloc_inode_node(sb);
	NOVA_ASSERT(new_node);
	new_node->range_low = new_node->range_high = internal_ino;
	ret = nova_insert_inodetree(sbi, new_node, cpu);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_inode_node(sb, new_node);
		goto finish;
	}
	header_tree->num_range_node_inode++;

finish:
	return ret;
}

static void nova_destroy_range_node_tree(struct super_block *sb,
	struct rb_root *tree)
{
	struct nova_range_node *curr;
	struct rb_node *temp;

	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}
}

static void nova_destroy_blocknode_tree(struct super_block *sb, int cpu)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	nova_destroy_range_node_tree(sb, &free_list->block_free_tree);
}

static void nova_destroy_blocknode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		nova_destroy_blocknode_tree(sb, i);
	}

	nova_destroy_blocknode_tree(sb, SHARED_CPU);
}

static int nova_init_blockmap_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct free_list *free_list;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *blknode;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_p;
	u64 cpuid;
	int ret;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
			ret = -EINVAL;
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
		ret = nova_insert_blocktree(sbi,
				&free_list->block_free_tree, blknode);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_blocknode(sb, blknode);
			NOVA_ASSERT(0);
			nova_destroy_blocknode_trees(sb);
			goto out;
		}
		free_list->num_blocknode++;
		if (free_list->num_blocknode == 1)
			free_list->first_node = blknode;
		free_list->num_free_blocks +=
			blknode->range_high - blknode->range_low + 1;
		curr_p += sizeof(struct nova_range_node_lowhigh);
	}
out:
	nova_free_inode_log(sb, pi);
	return ret;
}

static void nova_destroy_inode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct header_tree *header_tree;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		header_tree = &sbi->header_trees[i];
		nova_destroy_range_node_tree(sb,
					&header_tree->inode_inuse_tree);
	}
}

#define CPUID_MASK 0xff00000000000000

static int nova_init_inode_list_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST1_INO);
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *range_node;
	struct header_tree *header_tree;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	unsigned long num_inode_node = 0;
	u64 curr_p;
	unsigned long cpuid;
	int ret;

	sbi->s_inodes_used_count = 0;
	curr_p = pi->log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, size)) {
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

		cpuid = (entry->range_low & CPUID_MASK) >> 56;
		if (cpuid >= sbi->cpus) {
			nova_err(sb, "Invalid cpuid %lu\n", cpuid);
			nova_free_inode_node(sb, range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		range_node->range_low = entry->range_low & ~CPUID_MASK;
		range_node->range_high = entry->range_high;
		ret = nova_insert_inodetree(sbi, range_node, cpuid);
		if (ret) {
			nova_err(sb, "%s failed, %d\n", __func__, cpuid);
			nova_free_inode_node(sb, range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		sbi->s_inodes_used_count +=
			range_node->range_high - range_node->range_low + 1;
		num_inode_node++;

		header_tree = &sbi->header_trees[cpuid];
		header_tree->num_range_node_inode++;
		if (!header_tree->first_inode_range)
			header_tree->first_inode_range = range_node;

		curr_p += sizeof(struct nova_range_node_lowhigh);
	}

	nova_dbg("%s: %lu inode nodes\n", __func__, num_inode_node);
out:
	nova_free_inode_log(sb, pi);
	return ret;
}

static bool nova_can_skip_full_scan(struct super_block *sb)
{
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	int ret;

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	ret = nova_init_blockmap_from_inode(sb);
	if (ret) {
		nova_err(sb, "init blockmap failed, "
				"fall back to DFS recovery\n");
		return false;
	}

	ret = nova_init_inode_list_from_inode(sb);
	if (ret) {
		nova_err(sb, "init inode list failed, "
				"fall back to DFS recovery\n");
		nova_destroy_blocknode_trees(sb);
		return false;
	}

	return true;
}

static u64 nova_append_range_node_entry(struct super_block *sb,
	struct nova_range_node *curr, u64 tail, unsigned long cpuid)
{
	u64 curr_p;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	struct nova_range_node_lowhigh *entry;
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);

	curr_p = tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		nova_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_range_node_lowhigh *)nova_get_block(sb, curr_p);
	entry->range_low = cpu_to_le64(curr->range_low);
	if (cpuid)
		entry->range_low |= cpu_to_le64(cpuid << 56);
	entry->range_high = cpu_to_le64(curr->range_high);
	nova_dbgv("append entry block low 0x%lx, high 0x%lx\n",
			curr->range_low, curr->range_high);

	nova_flush_buffer(entry, sizeof(struct nova_range_node_lowhigh), 0);
out:
	NOVA_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

static u64 nova_save_range_nodes_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail, unsigned long cpuid)
{
	struct nova_range_node *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		curr_entry = nova_append_range_node_entry(sb, curr,
						temp_tail, cpuid);
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
								temp_tail, 0);
	return temp_tail;
}

void nova_save_inode_list_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST1_INO);
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long num_blocks;
	unsigned long num_nodes = 0;
	struct header_tree *header_tree;
	unsigned long i;
	u64 temp_tail;
	u64 new_block;
	int allocated;

	for (i = 0; i < sbi->cpus; i++) {
		header_tree = &sbi->header_trees[i];
		num_nodes += header_tree->num_range_node_inode;
	}

	num_blocks = num_nodes / RANGENODE_PER_PAGE;
	if (num_nodes % RANGENODE_PER_PAGE)
		num_blocks++;

	allocated = nova_allocate_inode_log_pages(sb, pi, num_blocks,
						&new_block);
	if (allocated != num_blocks) {
		nova_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	pi->log_head = new_block;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		header_tree = &sbi->header_trees[i];
		temp_tail = nova_save_range_nodes_to_log(sb,
				&header_tree->inode_inuse_tree, temp_tail, i);
	}

	nova_update_tail(pi, temp_tail);

	nova_dbg("%s: %lu inode nodes, pi head 0x%llx, tail 0x%llx\n",
		__func__, num_nodes, pi->log_head, pi->log_tail);
}

void nova_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super;
	struct free_list *free_list;
	unsigned long num_blocknode = 0;
	unsigned long num_pages;
	int allocated;
	u64 new_block = 0;
	u64 temp_tail;
	int i;

	/* Allocate log pages before save blocknode mappings */
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
		nova_dbgv("%s: free list %d: %lu nodes\n", __func__,
				i, free_list->num_blocknode);
	}

	free_list = nova_get_free_list(sb, SHARED_CPU);
	num_blocknode += free_list->num_blocknode;
	nova_dbgv("%s: shared list: %lu nodes\n", __func__,
				free_list->num_blocknode);

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

	nova_dbg("%s: %lu blocknodes, %lu log pages, pi head 0x%llx, "
		"tail 0x%llx\n", __func__, num_blocknode, num_pages,
		pi->log_head, pi->log_tail);
}

static int nova_insert_blocknode_map(struct super_block *sb,
	int cpuid, unsigned long low, unsigned long high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	struct rb_root *tree;
	struct nova_range_node *blknode = NULL;
	unsigned long num_blocks = 0;
	int ret;

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
	ret = nova_insert_blocktree(sbi, tree, blknode);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_blocknode(sb, blknode);
		goto out;
	}
	if (!free_list->first_node)
		free_list->first_node = blknode;
	free_list->num_blocknode++;
	free_list->num_free_blocks += num_blocks;
out:
	return ret;
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

static void free_bm(struct scan_bitmap *bm)
{
	kfree(bm->scan_bm_4K.bitmap);
	kfree(bm->scan_bm_2M.bitmap);
	kfree(bm->scan_bm_1G.bitmap);
	kfree(bm);
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

	return bm;
}

/************************** NOVA recovery ****************************/

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

unsigned int nova_free_header_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct header_tree *header_tree;
	struct nova_inode_info_header *sih;
	struct nova_inode_info_header *sih_array[FREE_BATCH];
	unsigned long ino = 0;
	int nr_sih;
	unsigned int freed = 0;
	int cpu;
	int i;
	void *ret;

	for (cpu = 0; cpu < sbi->cpus; cpu++) {
		header_tree = &sbi->header_trees[cpu];
		ino = 0;

		do {
			nr_sih = radix_tree_gang_lookup(&header_tree->root,
					(void **)sih_array, ino / sbi->cpus,
					FREE_BATCH);
			for (i = 0; i < nr_sih; i++) {
				sih = sih_array[i];
				BUG_ON(!sih);
				ino = sih->ino;
				ret = radix_tree_delete(&header_tree->root,
							ino / sbi->cpus);
				BUG_ON(!ret || ret != sih);
				nova_free_dram_resource(sb, sih);
				nova_free_header(sb, sih);
				freed++;
			}
			ino++;
		} while (nr_sih == FREE_BATCH);
	}

	nova_dbg("%s: freed %u\n", __func__, freed);
	return freed;
}

int nova_assign_info_header(struct super_block *sb, unsigned long ino,
	struct nova_inode_info_header **sih, u16 i_mode, int need_lock)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct header_tree *header_tree;
	struct nova_inode_info_header *old_sih, *new_sih;
	unsigned long internal_ino;
	int cpu;
	int ret = 0;

	nova_dbgv("assign_header ino %lu\n", ino);

	cpu = ino % sbi->cpus;
	internal_ino = ino / sbi->cpus;
	header_tree = &sbi->header_trees[cpu];

	if (need_lock)
		mutex_lock(&header_tree->inode_table_mutex);

	old_sih = radix_tree_lookup(&header_tree->root, internal_ino);
	if (old_sih) {
		old_sih->i_mode = i_mode;
		*sih = old_sih;
	} else {
		new_sih = nova_alloc_header(sb, i_mode);
		if (!new_sih) {
			ret = -ENOMEM;
			goto out;
		}
		ret = radix_tree_insert(&header_tree->root, internal_ino,
						new_sih);
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
		mutex_unlock(&header_tree->inode_table_mutex);

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

	nova_dbgv("%s: inode %lu, addr 0x%llx, valid %d, "
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
		/* Treat symlink files as normal files */
		nova_assign_info_header(sb, nova_ino, &sih,
				__le16_to_cpu(pi->i_mode), need_lock);
		nova_rebuild_file_inode_tree(sb, pi, pi_addr, sih, bm);
		break;
	default:
		nova_assign_info_header(sb, nova_ino, &sih,
				__le16_to_cpu(pi->i_mode), need_lock);
		/* In case of special inode, walk the log */
		if (pi->log_head)
			nova_rebuild_file_inode_tree(sb, pi, pi_addr, sih, bm);
		sih->pi_addr = pi_addr;
		break;
	}

	return 0;
}

/*********************** DFS recovery *************************/

static int nova_dfs_recovery_crawl(struct super_block *sb,
	struct scan_bitmap *bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	struct inode_table *inode_table;
	unsigned long curr_addr;
	unsigned long num_inodes_per_page;
	unsigned int data_bits;
	u64 curr;
	u64 root_addr = NOVA_ROOT_INO_START;
	u64 pi_addr;
	unsigned long i, cpu;
	int ret;

	nova_dbg_verbose("%s: rebuild alive inodes\n", __func__);

	/* First recover the root iode */
	ret = nova_recover_inode(sb, root_addr, bm, smp_processor_id(), 0);

	pi = nova_get_inode_table(sb);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	num_inodes_per_page = 1 << (data_bits - NOVA_INODE_BITS);

	curr = pi->log_head;
	while (curr) {
		/*
		 * Note: The inode log page is allocated in 2MB granularity,
		 * but not aligned on 2MB boundary
		 */
		for (i = 0; i < 512; i++)
			set_bm((curr >> PAGE_SHIFT) + i, bm, BM_4K);

		for (i = 0; i < num_inodes_per_page; i++) {
			pi_addr = curr + i * NOVA_INODE_SIZE;
			ret = nova_recover_inode(sb, pi_addr, bm,
						smp_processor_id(), 0);
		}

		curr_addr = (unsigned long)nova_get_block(sb, curr);
		/* Next page pointer in the last 8 bytes of the superpage */
		curr_addr += 2097152 - 8;
		curr = *(u64 *)(curr_addr);
	}

	for (cpu = 0; cpu < sbi->cpus; cpu++) {
		inode_table = nova_get_inode_table1(sb, cpu);
		if (!inode_table)
			return -EINVAL;

		curr = inode_table->log_head;
		while (curr) {
			/*
			 * Note: The inode log page is allocated in 2MB
			 * granularity, but not aligned on 2MB boundary.
			 */
			for (i = 0; i < 512; i++)
				set_bm((curr >> PAGE_SHIFT) + i, bm, BM_4K);
#if 0
			for (i = 0; i < num_inodes_per_page; i++) {
				pi_addr = curr + i * NOVA_INODE_SIZE;
				ret = nova_recover_inode(sb, pi_addr, bm,
							smp_processor_id(), 0);
			}
#endif
			curr_addr = (unsigned long)nova_get_block(sb, curr);
			/* Next page resides at the last 8 bytes */
			curr_addr += 2097152 - 8;
			curr = *(u64 *)(curr_addr);
		}
	}

	return ret;
}

int nova_dfs_recovery(struct super_block *sb, struct scan_bitmap *bm)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	struct ptr_pair *pair;
	int ret;
	int i;

	sbi->s_inodes_used_count = 0;

	/* Initialize inuse inode list */
	if (nova_init_inode_inuse_list(sb) < 0)
		return -EINVAL;

	/* Handle special inodes */
	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->log_head = pi->log_tail = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (!pair)
			return -EINVAL;

		set_bm(pair->journal_head >> PAGE_SHIFT, bm, BM_4K);
	}

	PERSISTENT_BARRIER();
	ret = nova_dfs_recovery_crawl(sb, bm);

	nova_dbg("DFS recovery total recovered %lu\n",
				sbi->s_inodes_used_count);
	return ret;
}

/*********************** Singlethread recovery *************************/

static u64 nova_get_last_ino(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct header_tree *header_tree;
	struct nova_range_node *curr;
	struct rb_node *temp;
	u64 max_ino = 0;
	u64 ino;
	int cpu;

	for (cpu = 0; cpu < sbi->cpus; cpu++) {
		header_tree = &sbi->header_trees[cpu];
		
		/* Save in increasing order */
		temp = rb_last(&header_tree->inode_inuse_tree);
		if (!temp)
			continue;

		curr = container_of(temp, struct nova_range_node, node);
		ino = le64_to_cpu(curr->range_high);
		ino = ino * sbi->cpus + cpu;
		if (ino > max_ino)
			max_ino = ino;
	}

	return max_ino;
}

int *processed;

static int nova_inode_table_singlethread_crawl(struct super_block *sb)
{
	u64 root_addr = NOVA_ROOT_INO_START;
	u64 pi_addr;
	u64 last_ino, i;
	int ret;

	nova_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	last_ino = nova_get_last_ino(sb);

	nova_dbg_verbose("Last inode %llu\n", last_ino);

	/* First recover the root iode */
	ret = nova_recover_inode(sb, root_addr, NULL, smp_processor_id(), 0);
	processed[smp_processor_id()]++;

	for (i = NOVA_NORMAL_INODE_START; i <= last_ino; i++) {
		ret = nova_get_inode_address(sb, i, &pi_addr, 0);
		if (ret) {
			nova_err(sb, "%s: get inode %llu address failed\n",
					__func__, i);
			break;
		}
		ret = nova_recover_inode(sb, pi_addr, NULL,
						smp_processor_id(), 0);
		processed[smp_processor_id()]++;
	}

	return ret;
}

int nova_singlethread_recovery(struct super_block *sb)
{
	int cpus = num_online_cpus();
	int i, total = 0;
	int ret = 0;

	processed = kzalloc(cpus * sizeof(int), GFP_KERNEL);
	if (!processed)
		return -ENOMEM;

	ret = nova_inode_table_singlethread_crawl(sb);

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

static int nova_inode_table_multithread_crawl(struct super_block *sb,
	int cpus)
{
	struct task_ring *ring = NULL;
	u64 root_addr = NOVA_ROOT_INO_START;
	u64 pi_addr;
	u64 last_ino, i;
	int ret = 0;

	nova_dbg_verbose("%s: rebuild alive inodes\n", __func__);
	last_ino = nova_get_last_ino(sb);

	nova_dbg_verbose("Last inode %llu\n", last_ino);

	/* First recover the root iode */
	ring = &task_rings[0];
	task_ring_enqueue(ring, root_addr);
	wake_up_interruptible(&ring->assign_wq);

	for (i = NOVA_NORMAL_INODE_START; i <= last_ino; i++) {
		ret = nova_get_inode_address(sb, i, &pi_addr, 0);
		if (ret) {
			nova_err(sb, "%s: get inode %llu address failed\n",
					__func__, i);
			break;
		}

		while ((ring = get_free_ring(cpus, ring)) == NULL) {
			wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
		}

		task_ring_enqueue(ring, pi_addr);
		wake_up_interruptible(&ring->assign_wq);
	}

	return ret;
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
	int cpus;
	int ret;

	cpus = num_online_cpus();
	nova_dbgv("%s: %d cpus\n", __func__, cpus);

	ret = allocate_resources(sb, cpus);
	if (ret)
		return ret;

	ret = nova_inode_table_multithread_crawl(sb, cpus);

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
