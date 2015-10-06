/*
 * NOVA File System statistics
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

#include "nova.h"

const char *Timingstring[TIMING_NUM] = 
{
	"init",
	"mount",
	"ioremap",
	"new_init",
	"recovery",

	"create",
	"lookup",
	"link",
	"unlink",
	"symlink",
	"mkdir",
	"rmdir",
	"mknod",
	"rename",
	"readdir",
	"add_entry",
	"remove_entry",
	"setattr",

	"dax_read",
	"cow_write",
	"copy_to_nvmm",

	"memcpy_read_nvmm",
	"memcpy_write_nvmm",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	"new_data_blocks",
	"new_log_blocks",
	"free_data_blocks",
	"free_log_blocks",

	"logging",
	"append_inode_entry",
	"inode_log_gc",
	"check_invalid_log",

	"find_cache_page",
	"assign_blocks",
	"fsync",
	"direct_IO",
	"delete_file_tree",
	"delete_dir_tree",
	"new_vfs_inode",
	"new_nova_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",
	"mmap_page_fault",
};

unsigned long long Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];
unsigned long alloc_steps;
unsigned long free_steps;
unsigned long write_breaks;
unsigned long long read_bytes;
unsigned long long cow_write_bytes;
unsigned long long fsync_bytes;
unsigned long long checked_pages;
unsigned long gc_pages;
unsigned long alloc_data_pages;
unsigned long free_data_pages;
unsigned long alloc_log_pages;
unsigned long free_log_pages;
atomic64_t fsync_pages = ATOMIC_INIT(0);
atomic64_t header_alloc = ATOMIC_INIT(0);
atomic64_t header_free = ATOMIC_INIT(0);
atomic64_t range_alloc = ATOMIC_INIT(0);
atomic64_t range_free = ATOMIC_INIT(0);

void nova_print_alloc_stats(struct super_block *sb)
{
	printk("=========== NOVA allocation stats ===========\n");
	printk("Alloc %llu, alloc steps %lu, average %llu\n",
		Countstats[new_data_blocks_t], alloc_steps,
		Countstats[new_data_blocks_t] ?
			alloc_steps / Countstats[new_data_blocks_t] : 0);
	printk("Free %llu, free steps %lu, average %llu\n",
		Countstats[free_data_t], free_steps,
		Countstats[free_data_t] ?
			free_steps / Countstats[free_data_t] : 0);
	printk("Garbage collection %llu, check pages %llu, average %llu,\n"
		"free pages %lu, average %llu\n",
		Countstats[log_gc_t], checked_pages,
		Countstats[log_gc_t] ?
			checked_pages / Countstats[log_gc_t] : 0,
		gc_pages, Countstats[log_gc_t] ?
			gc_pages / Countstats[log_gc_t] : 0);
	printk("Allocated %lu data pages\n", alloc_data_pages);
	printk("Freed %lu data pages\n", free_data_pages);
	printk("Allocated %lu log pages\n", alloc_log_pages);
	printk("Freed %lu log pages\n", free_log_pages);
	printk("Allocated %ld info headers\n",
			atomic64_read(&header_alloc));
	printk("Allocated %ld range nodes\n",
			atomic64_read(&range_alloc));
}

void nova_print_IO_stats(struct super_block *sb)
{
	printk("=========== NOVA I/O stats ===========\n");
	printk("Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], read_bytes,
		Countstats[dax_read_t] ?
			read_bytes / Countstats[dax_read_t] : 0);
	printk("COW write %llu, bytes %llu, average %llu, "
		"write breaks %lu, average %llu\n",
		Countstats[cow_write_t], cow_write_bytes,
		Countstats[cow_write_t] ?
			cow_write_bytes / Countstats[cow_write_t] : 0,
		write_breaks, Countstats[cow_write_t] ?
			write_breaks / Countstats[cow_write_t] : 0);
	printk("Copy to NVMM %llu, bytes %llu, average %llu\n",
		Countstats[copy_to_nvmm_t], fsync_bytes,
		Countstats[copy_to_nvmm_t] ?
			fsync_bytes / Countstats[copy_to_nvmm_t] : 0);
	printk("Fsync %ld pages\n", atomic64_read(&fsync_pages));
}

void nova_print_timing_stats(struct super_block *sb)
{
	int i;

	printk("======== NOVA kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		if (measure_timing || Timingstats[i]) {
			printk("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			printk("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	nova_print_alloc_stats(sb);
	nova_print_IO_stats(sb);
}

void nova_clear_stats(void)
{
	int i;

	printk("======== Clear NOVA kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
	}
}

void nova_print_inode_log(struct super_block *sb, struct inode *inode)
{
	struct nova_inode *pi;
	size_t entry_size = sizeof(struct nova_file_write_entry);
	u64 curr;

	pi = nova_get_inode(sb, inode);
	if (pi->log_tail == 0)
		return;

	curr = pi->log_head;
	nova_dbg("Pi %lu: log head block @ %llu, tail @ block %llu, %llu\n",
			inode->i_ino, curr >> PAGE_SHIFT,
			pi->log_tail >> PAGE_SHIFT, pi->log_tail);
	while (curr != pi->log_tail) {
		if ((curr & (PAGE_SIZE - 1)) == LAST_ENTRY) {
			struct nova_inode_page_tail *tail =
					nova_get_block(sb, curr);
			nova_dbg("Log tail. Next page @ block %llu\n",
					tail->next_page >> PAGE_SHIFT);
			curr = tail->next_page;
		} else {
			struct nova_file_write_entry *entry =
					nova_get_block(sb, curr);
			nova_dbg("entry @ %llu: offset %u, size %u, "
				"blocknr %llu, invalid count %u\n",
				(curr & (PAGE_SIZE - 1)) / entry_size,
				entry->pgoff, entry->num_pages,
				entry->block >> PAGE_SHIFT,
				entry->invalid_pages);
			curr += entry_size;
		}
	}
}

void nova_print_inode_log_pages(struct super_block *sb, struct inode *inode)
{
	struct nova_inode *pi;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	struct nova_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;
	int used = count;

	pi = nova_get_inode(sb, inode);
	if (pi->log_tail == 0) {
		nova_dbg("Pi %lu has no log\n", inode->i_ino);
		return;
	}

	curr = pi->log_head;
	nova_dbg("Pi %lu: log head @ 0x%llx, tail @ 0x%llx\n",
			inode->i_ino, curr, pi->log_tail);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	while ((next = curr_page->page_tail.next_page) != 0) {
		nova_dbg_verbose("Current page 0x%llx, next page 0x%llx\n",
			curr >> PAGE_SHIFT, next >> PAGE_SHIFT);
		if (pi->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
			used = count;
		curr = next;
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr);
		count++;
	}
	if (pi->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
		used = count;
	nova_dbg("Pi %lu: log used %d pages, has %d pages, "
		"si reports %lu pages\n", inode->i_ino, used, count,
		sih->log_pages);
}

void nova_print_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;

	nova_dbg("======== NOVA per-CPU free list allocation stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		nova_dbg("Free list %d: block start %lu, block end %lu, "
			"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		nova_dbg("Free list %d: alloc count %lu, "
			"free count %lu, allocated blocks %lu, "
			"freed blocks %lu\n", i,
			free_list->alloc_count,	free_list->free_count,
			free_list->allocated_blocks, free_list->freed_blocks);
	}

	i = SHARED_CPU;
	free_list = nova_get_free_list(sb, i);
	nova_dbg("Free list %d: block start %lu, block end %lu, "
		"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
		i, free_list->block_start, free_list->block_end,
		free_list->block_end - free_list->block_start + 1,
		free_list->num_free_blocks, free_list->num_blocknode);

	nova_dbg("Free list %d: alloc count %lu, "
		"free count %lu, allocated blocks %lu, "
		"freed blocks %lu\n", i,
		free_list->alloc_count,	free_list->free_count,
		free_list->allocated_blocks, free_list->freed_blocks);
}

void nova_detect_memory_leak(struct super_block *sb)
{
	if (atomic64_read(&header_alloc) != atomic64_read(&header_free))
		nova_dbg("%s: inode header memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&header_alloc),
			atomic64_read(&header_free));
	if (atomic64_read(&range_alloc) != atomic64_read(&range_free))
		nova_dbg("%s: range node memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&range_alloc),
			atomic64_read(&range_free));
}
