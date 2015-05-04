#include "pmfs.h"

const char *Timingstring[TIMING_NUM] = 
{
	"ioremap",

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
	"new_inode",
	"add_entry",
	"remove_entry",
	"setattr",

	"xip_read",
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
	"new_meta_block",
	"new_cache_page",
	"free_data_blocks",
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

void pmfs_print_blocknode_list(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct list_head *head = &(sbi->block_inuse_head);
	struct pmfs_blocknode *i;
	unsigned long count = 0;

	printk("=========== PMFS blocknode stats ===========\n");
	mutex_lock(&sbi->s_lock);
	list_for_each_entry(i, head, link) {
		count++;
		pmfs_dbg_verbose("node low %lu, high %lu, size %lu\n",
			i->block_low, i->block_high,
			i->block_high - i->block_low + 1);
	}
	mutex_unlock(&sbi->s_lock);
	printk("All: %lu nodes\n", count);
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
}

void pmfs_print_IO_stats(struct super_block *sb)
{
	printk("=========== PMFS I/O stats ===========\n");
	printk("Read %llu, bytes %llu, average %llu\n",
		Countstats[xip_read_t], read_bytes,
		Countstats[xip_read_t] ?
			read_bytes / Countstats[xip_read_t] : 0);
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

	pmfs_print_blocknode_list(sb);
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
	size_t entry_size = sizeof(struct pmfs_inode_entry);
	u64 curr;

	pi = pmfs_get_inode(sb, inode->i_ino);
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
			struct pmfs_inode_entry *entry =
					pmfs_get_block(sb, curr);
			pmfs_dbg("entry @ %llu: offset %u, size %u, "
				"blocknr %llu, invalid count %llu\n",
				(curr & (PAGE_SIZE - 1)) / entry_size,
				entry->pgoff, entry->num_pages,
				entry->block >> PAGE_SHIFT,
				GET_INVALID(entry->block));
			curr += entry_size;
		}
	}
}

void pmfs_print_inode_log_page(struct super_block *sb, struct inode *inode)
{
	struct pmfs_inode *pi;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;
	int used = count;

	pi = pmfs_get_inode(sb, inode->i_ino);
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
			si->log_pages);
}

void pmfs_print_inode_log_blocknode(struct super_block *sb,
		struct inode *inode)
{
	struct pmfs_inode *pi;
	struct pmfs_inode_page_tail *tail;
	size_t entry_size = sizeof(struct pmfs_inode_entry);
	u64 curr;
	unsigned long count = 0;

	pi = pmfs_get_inode(sb, inode->i_ino);

	if (pi->log_tail == 0)
		goto out;

	curr = pi->log_head;
	pmfs_dbg("Pi %lu: log head @ 0x%llx, tail @ 0x%llx\n", inode->i_ino,
			curr >> PAGE_SHIFT, pi->log_tail >> PAGE_SHIFT);
	do {
		tail = pmfs_get_block(sb, curr +
					entry_size * ENTRIES_PER_PAGE);
		pmfs_dbg("log block @ 0x%llx\n", curr >> PAGE_SHIFT);
		curr = tail->next_page;
		count++;
		if ((curr >> PAGE_SHIFT) == 0)
			break;
	} while ((curr >> PAGE_SHIFT) != (pi->log_tail >> PAGE_SHIFT));

out:
	pmfs_dbg("All %lu pages\n", count);
}

void pmfs_detect_memory_leak(struct super_block *sb)
{
	if (Countstats[new_meta_block_t] != Countstats[free_meta_t])
		pmfs_dbg("%s: meta block memory leak! "
			"allocated %llu, freed %llu\n", __func__,
			Countstats[new_meta_block_t], Countstats[free_meta_t]);
	if (Countstats[new_cache_page_t] != Countstats[free_cache_t])
		pmfs_dbg("%s: cache block memory leak! "
			"allocated %llu, freed %llu\n", __func__,
			Countstats[new_cache_page_t], Countstats[free_cache_t]);
}
