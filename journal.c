/*
 * PMFS journaling facility. This file contains code to log changes to pmfs
 * meta-data to facilitate consistent meta-data updates against arbitrary
 * power and system failures.
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

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "pmfs.h"
#include "journal.h"

/**************************** Lite journal ******************************/

static u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct pmfs_lite_journal_entry);

	/* One page holds 64 entries with cacheline size */
	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

static void pmfs_recover_lite_journal_entry(struct super_block *sb,
	u64 addr, u64 value, u8 type)
{
	switch (type) {
		case 1:
			*(u8 *)pmfs_get_block(sb, addr) = (u8)value;
			break;
		case 2:
			*(u16 *)pmfs_get_block(sb, addr) = (u16)value;
			break;
		case 4:
			*(u32 *)pmfs_get_block(sb, addr) = (u32)value;
			break;
		case 8:
			*(u64 *)pmfs_get_block(sb, addr) = (u64)value;
			break;
		default:
			pmfs_dbg("%s: unknown data type %u\n",
					__func__, type);
			break;
	}

	pmfs_flush_buffer((void *)pmfs_get_block(sb, addr), CACHELINE_SIZE, 0);
}

void pmfs_print_lite_transaction(struct pmfs_lite_journal_entry *entry)
{
	int i;

	for (i = 0; i < 4; i++)
		pmfs_dbg_verbose("Entry %d: addr 0x%llx, value 0x%llx\n",
				i, entry->addrs[i], entry->values[i]);
}

/* Caller needs to grab lite_journal_mutex until commit. */
/* Do not fail, do not sleep. Make it fast! */
u64 pmfs_create_lite_transaction(struct super_block *sb,
	struct pmfs_lite_journal_entry *dram_entry1,
	struct pmfs_lite_journal_entry *dram_entry2,
	int entries)
{
	struct pmfs_inode *pi;
	struct pmfs_lite_journal_entry *entry;
	size_t size = sizeof(struct pmfs_lite_journal_entry);
	u64 new_tail, temp;;

	pi = pmfs_get_inode_by_ino(sb, PMFS_LITEJOURNAL_INO);
	if (pi->log_head == 0 || pi->log_head != pi->log_tail)
		BUG();

	temp = pi->log_head;
	entry = (struct pmfs_lite_journal_entry *)pmfs_get_block(sb,
							temp);

	pmfs_print_lite_transaction(dram_entry1);
	memcpy_to_pmem_nocache(entry, dram_entry1, size);

	if (entries == 2) {
		temp = next_lite_journal(temp);
		entry = (struct pmfs_lite_journal_entry *)pmfs_get_block(sb,
							temp);
		pmfs_print_lite_transaction(dram_entry2);
		memcpy_to_pmem_nocache(entry, dram_entry2, size);
	}

	new_tail = next_lite_journal(temp);
	pmfs_update_tail(pi, new_tail);
	return new_tail;
}

/* Caller needs to hold lite_journal_mutex until this returns. */
void pmfs_commit_lite_transaction(struct super_block *sb, u64 tail)
{
	struct pmfs_inode *pi;

	pi = pmfs_get_inode_by_ino(sb, PMFS_LITEJOURNAL_INO);
	if (pi->log_tail != tail)
		BUG();

	pi->log_head = tail;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
}

static void pmfs_undo_lite_journal_entry(struct super_block *sb,
	struct pmfs_lite_journal_entry *entry)
{
	int i;
	u8 type;

	for (i = 0; i < 4; i++) {
		type = entry->addrs[i] >> 56;
		if (entry->addrs[i] && type) {
			pmfs_dbg("%s: recover entry %d\n", __func__, i);
			pmfs_recover_lite_journal_entry(sb, entry->addrs[i],
					entry->values[i], type);
		}
	}
}

static int pmfs_recover_lite_journal(struct super_block *sb,
	struct pmfs_inode *pi, int recover)
{
	struct pmfs_lite_journal_entry *entry;
	u64 temp;

	entry = (struct pmfs_lite_journal_entry *)pmfs_get_block(sb,
							pi->log_head);
	pmfs_undo_lite_journal_entry(sb, entry);

	if (recover == 2) {
		temp = next_lite_journal(pi->log_head);
		entry = (struct pmfs_lite_journal_entry *)pmfs_get_block(sb,
							temp);
		pmfs_undo_lite_journal_entry(sb, entry);
	}

	PERSISTENT_BARRIER();
	pmfs_update_tail(pi, pi->log_head);
	return 0;
}

int pmfs_lite_journal_soft_init(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	struct pmfs_inode *pi;
	u64 temp;

	mutex_init(&sbi->lite_journal_mutex);
	pi = pmfs_get_inode_by_ino(sb, PMFS_LITEJOURNAL_INO);

	if (pi->log_head == pi->log_tail)
		return 0;

	/* We only allow up to two uncommited entries */
	temp = next_lite_journal(pi->log_head);
	if (pi->log_tail == temp) {
		pmfs_recover_lite_journal(sb, pi, 1);
		return 0;
	}

	temp = next_lite_journal(temp);
	if (pi->log_tail == temp) {
		pmfs_recover_lite_journal(sb, pi, 2);
		return 0;
	}

	/* We are in trouble */
	pmfs_dbg("%s: lite journal head 0x%llx, tail 0x%llx\n",
			__func__, pi->log_head, pi->log_tail);
	return -EINVAL;
}

int pmfs_lite_journal_hard_init(struct super_block *sb)
{
	struct pmfs_inode *pi;
	unsigned long blocknr = 0;
	unsigned long pmfs_ino;
	int allocated;
	u64 block;

	pi = pmfs_get_inode_by_ino(sb, PMFS_LITEJOURNAL_INO);
	pmfs_ino = PMFS_LITEJOURNAL_INO;
	allocated = pmfs_new_log_blocks(sb, pmfs_ino, &blocknr, 1,
						PMFS_BLOCK_TYPE_4K, 1);
	pmfs_dbg_verbose("%s: allocate log @ 0x%lx\n", __func__, blocknr);
	if (allocated != 1 || blocknr == 0)
		return -ENOSPC;

	pi->i_blocks = 1;
	block = pmfs_get_block_off(sb, blocknr,	PMFS_BLOCK_TYPE_4K);
	pi->log_head = pi->log_tail = block;
	pmfs_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	return pmfs_lite_journal_soft_init(sb);
}

