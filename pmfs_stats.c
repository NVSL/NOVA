#include "pmfs.h"

const char *Timingstring[TIMING_NUM] = 
{
	"xip_read",
	"xip_write",
	"xip_write_fast",
	"memcpy_read",
	"memcpy_write",
	"logging",
	"new_blocks",
	"cow_write",
};

unsigned long long Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];

void pmfs_print_timing_stats(void)
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
	while (curr != pi->log_tail) {
		struct pmfs_inode_entry *entry = pmfs_get_block(sb, curr);
		pmfs_dbg("entry @ %llu: offset %llu, size %lu, block %llu, "
			"flags %llu\n",
			(curr & (PAGE_SIZE - 1)) / entry_size,
			entry->offset, entry->size, entry->block, entry->flags);
		if ((curr & (PAGE_SIZE - 1)) == LAST_ENTRY) {
			curr = ((struct pmfs_inode_page_tail *)entry)->next_page;
		} else {
			curr += entry_size;
		}
	}

out:
	mutex_unlock(&inode->i_mutex);
}
