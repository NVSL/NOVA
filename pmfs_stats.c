#include "pmfs.h"

const char *Timingstring[TIMING_NUM] = 
{
	"xip_read",
	"xip_write",
	"xip_write_fast",
	"memcpy_read",
	"memcpy_write",
	"logging",
	"new_meta_blocks",
	"new_data_blocks",
	"cow_write",
	"assign_blocks",
	"free_data_blocks",
};

unsigned long long Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];
unsigned long alloc_steps;
unsigned long free_steps;

void pmfs_print_blocknode_list(struct file *filp)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
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
	printk("alloc %llu, alloc steps %lu, average %llu\n",
		Countstats[7], alloc_steps,
		Countstats[7] ? alloc_steps / Countstats[7] : 0);
	printk("free %llu, free steps %lu, average %llu\n",
		Countstats[10],free_steps,
		Countstats[10] ? free_steps / Countstats[10] : 0);
}

void pmfs_print_timing_stats(struct file *filp)
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

	pmfs_print_blocknode_list(filp);
}

void pmfs_clear_stats(struct file *filp)
{
	int i;

	printk("======== Clear PMFS kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
	}
}

void pmfs_print_inode_log(struct file *filp)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	size_t entry_size = sizeof(struct pmfs_inode_entry);
	u64 curr;

	mutex_lock(&inode->i_mutex);
	pi = pmfs_get_inode(sb, inode->i_ino);

	if (pi->log_tail == 0)
		goto out;

	curr = pi->log_head;
	pmfs_dbg("Pi %lu: log head @ %llu, tail @ %llu\n", inode->i_ino,
			curr, pi->log_tail);
	while (curr != pi->log_tail) {
		if ((curr & (PAGE_SIZE - 1)) == LAST_ENTRY) {
			struct pmfs_inode_page_tail *tail =
					pmfs_get_block(sb, curr);
			pmfs_dbg("Log tail. Next page @ block %llu\n",
					tail->next_page);
			curr = tail->next_page;
		} else {
			struct pmfs_inode_entry *entry =
					pmfs_get_block(sb, curr);
			pmfs_dbg("entry @ %llu: offset %u, size %u, "
				"block 0x%llx, invalid count %llu\n",
				(curr & (PAGE_SIZE - 1)) / entry_size,
				entry->pgoff, entry->num_pages,
				BLOCK_OFF(entry->block),
				GET_INVALID(entry->block));
			curr += entry_size;
		}
	}

out:
	mutex_unlock(&inode->i_mutex);
}

void pmfs_print_inode_log_blocknode(struct file *filp)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	struct pmfs_inode_page_tail *tail;
	size_t entry_size = sizeof(struct pmfs_inode_entry);
	u64 curr;
	unsigned long count = 0;

	mutex_lock(&inode->i_mutex);
	pi = pmfs_get_inode(sb, inode->i_ino);

	if (pi->log_tail == 0)
		goto out;

	curr = pi->log_head;
	pmfs_dbg("Pi %lu: log head @ %llu, tail @ %llu\n", inode->i_ino,
			curr >> PAGE_SHIFT, pi->log_tail >> PAGE_SHIFT);
	do {
		tail = pmfs_get_block(sb, curr +
					entry_size * ENTRIES_PER_PAGE);
		pmfs_dbg("log block @ %llu\n", curr >> PAGE_SHIFT);
		curr = tail->next_page;
		count++;
	} while ((curr >> PAGE_SHIFT) != (pi->log_tail >> PAGE_SHIFT));

out:
	mutex_unlock(&inode->i_mutex);
	pmfs_dbg("All %lu pages\n", count);
}
