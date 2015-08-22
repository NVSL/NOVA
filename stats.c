#include "pmfs.h"

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
	"page_cache_write",
	"copy_to_nvmm",

	"memcpy_read_nvmm",
	"memcpy_read_dram",
	"memcpy_write_nvmm",
	"memcpy_write_dram",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	"new_data_blocks",
	"new_log_blocks",
	"new_meta_block",
	"new_cache_page",
	"free_data_blocks",
	"free_log_blocks",
	"free_meta_blocks",
	"free_cache_blocks",

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
	"new_pmfs_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",
	"mmap_page_fault",
	"malloc_test",
};

unsigned long long Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];
unsigned long alloc_steps;
unsigned long free_steps;
unsigned long write_breaks;
unsigned long long read_bytes;
unsigned long long cow_write_bytes;
unsigned long long page_cache_write_bytes;
unsigned long long fsync_bytes;
unsigned long long checked_pages;
unsigned long gc_pages;
unsigned long alloc_data_pages;
unsigned long free_data_pages;
unsigned long alloc_log_pages;
unsigned long free_log_pages;
atomic64_t fsync_pages = ATOMIC_INIT(0);
atomic64_t meta_alloc = ATOMIC_INIT(0);
atomic64_t meta_free = ATOMIC_INIT(0);
atomic64_t cache_alloc = ATOMIC_INIT(0);
atomic64_t cache_free = ATOMIC_INIT(0);
atomic64_t mempair_alloc = ATOMIC_INIT(0);
atomic64_t mempair_free = ATOMIC_INIT(0);
atomic64_t dirnode_alloc = ATOMIC_INIT(0);
atomic64_t dirnode_free = ATOMIC_INIT(0);
atomic64_t header_alloc = ATOMIC_INIT(0);
atomic64_t header_free = ATOMIC_INIT(0);

void pmfs_print_alloc_stats(struct super_block *sb)
{
	printk("=========== PMFS allocation stats ===========\n");
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
}

void pmfs_print_IO_stats(struct super_block *sb)
{
	printk("=========== PMFS I/O stats ===========\n");
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
	printk("Page cache write %llu, bytes %llu, average %llu, "
		"write breaks %lu, average %llu\n",
		Countstats[page_cache_write_t], page_cache_write_bytes,
		Countstats[page_cache_write_t] ?
		page_cache_write_bytes / Countstats[page_cache_write_t] : 0,
		write_breaks, Countstats[page_cache_write_t] ?
			write_breaks / Countstats[page_cache_write_t] : 0);
	printk("Copy to NVMM %llu, bytes %llu, average %llu\n",
		Countstats[copy_to_nvmm_t], fsync_bytes,
		Countstats[copy_to_nvmm_t] ?
			fsync_bytes / Countstats[copy_to_nvmm_t] : 0);
	printk("Fsync %ld pages\n", atomic64_read(&fsync_pages));
}

void pmfs_print_timing_stats(struct super_block *sb)
{
	int i;

	printk("======== PMFS kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		if (measure_timing) {
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

	pmfs_print_alloc_stats(sb);
	pmfs_print_IO_stats(sb);
}

void pmfs_clear_stats(void)
{
	int i;

	printk("======== Clear PMFS kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
	}
}

void pmfs_print_inode_log(struct super_block *sb, struct inode *inode)
{
	struct pmfs_inode *pi;
	size_t entry_size = sizeof(struct pmfs_file_write_entry);
	u64 curr;

	pi = pmfs_get_inode(sb, inode);
	if (pi->log_tail == 0)
		return;

	curr = pi->log_head;
	pmfs_dbg("Pi %lu: log head block @ %llu, tail @ block %llu, %llu\n",
			inode->i_ino, curr >> PAGE_SHIFT,
			pi->log_tail >> PAGE_SHIFT, pi->log_tail);
	while (curr != pi->log_tail) {
		if ((curr & (PAGE_SIZE - 1)) == LAST_ENTRY) {
			struct pmfs_inode_page_tail *tail =
					pmfs_get_block(sb, curr);
			pmfs_dbg("Log tail. Next page @ block %llu\n",
					tail->next_page >> PAGE_SHIFT);
			curr = tail->next_page;
		} else {
			struct pmfs_file_write_entry *entry =
					pmfs_get_block(sb, curr);
			pmfs_dbg("entry @ %llu: offset %u, size %u, "
				"blocknr %llu, invalid count %u\n",
				(curr & (PAGE_SIZE - 1)) / entry_size,
				entry->pgoff, entry->num_pages,
				entry->block >> PAGE_SHIFT,
				entry->invalid_pages);
			curr += entry_size;
		}
	}
}

void pmfs_print_inode_log_pages(struct super_block *sb, struct inode *inode)
{
	struct pmfs_inode *pi;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct pmfs_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;
	int used = count;

	pi = pmfs_get_inode(sb, inode);
	if (pi->log_tail == 0) {
		pmfs_dbg("Pi %lu has no log\n", inode->i_ino);
		return;
	}

	curr = pi->log_head;
	pmfs_dbg("Pi %lu: log head @ 0x%llx, tail @ 0x%llx\n",
			inode->i_ino, curr, pi->log_tail);
	curr_page = (struct pmfs_inode_log_page *)pmfs_get_block(sb, curr);
	while ((next = curr_page->page_tail.next_page) != 0) {
		pmfs_dbg_verbose("Current page 0x%llx, next page 0x%llx\n",
			curr >> PAGE_SHIFT, next >> PAGE_SHIFT);
		if (pi->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
			used = count;
		curr = next;
		curr_page = (struct pmfs_inode_log_page *)
			pmfs_get_block(sb, curr);
		count++;
	}
	if (pi->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
		used = count;
	pmfs_dbg("Pi %lu: log used %d pages, has %d pages, "
			"si reports %d pages\n", inode->i_ino, used, count,
			sih->log_pages);
}

void pmfs_print_free_lists(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct free_list *free_list;
	int i;

	pmfs_dbg("======== PMFS per-CPU free list allocation stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = pmfs_get_free_list(sb, i);
		pmfs_dbg("Free list %d: block start %lu, block end %lu, "
			"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		pmfs_dbg("Free list %d: alloc count %lu, "
			"free count %lu, allocated blocks %lu, "
			"freed blocks %lu\n", i,
			free_list->alloc_count,	free_list->free_count,
			free_list->allocated_blocks, free_list->freed_blocks);
	}

	i = SHARED_CPU;
	free_list = pmfs_get_free_list(sb, i);
	pmfs_dbg("Free list %d: block start %lu, block end %lu, "
		"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
		i, free_list->block_start, free_list->block_end,
		free_list->block_end - free_list->block_start + 1,
		free_list->num_free_blocks, free_list->num_blocknode);

	pmfs_dbg("Free list %d: alloc count %lu, "
		"free count %lu, allocated blocks %lu, "
		"freed blocks %lu\n", i,
		free_list->alloc_count,	free_list->free_count,
		free_list->allocated_blocks, free_list->freed_blocks);
}

void pmfs_detect_memory_leak(struct super_block *sb)
{
	if (atomic64_read(&meta_alloc) != atomic64_read(&meta_free))
		pmfs_dbg("%s: meta block memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&meta_alloc), atomic64_read(&meta_free));
	if (atomic64_read(&cache_alloc) != atomic64_read(&cache_free))
		pmfs_dbg("%s: cache block memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&cache_alloc),
			atomic64_read(&cache_free));
	if (atomic64_read(&mempair_alloc) != atomic64_read(&mempair_free))
		pmfs_dbg("%s: mempair memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&mempair_alloc),
			atomic64_read(&mempair_free));
	if (atomic64_read(&dirnode_alloc) != atomic64_read(&dirnode_free))
		pmfs_dbg("%s: dirnode memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&dirnode_alloc),
			atomic64_read(&dirnode_free));
	if (atomic64_read(&header_alloc) != atomic64_read(&header_free))
		pmfs_dbg("%s: inode header memory leak! "
			"allocated %ld, freed %ld\n", __func__,
			atomic64_read(&header_alloc),
			atomic64_read(&header_free));
}
