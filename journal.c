/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
 *
 * Copyright 2015 NVSL, UC San Diego
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
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
#include "nova.h"
#include "journal.h"

/**************************** Lite journal ******************************/

static u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct nova_lite_journal_entry);

	/* One page holds 64 entries with cacheline size */
	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

static void nova_recover_lite_journal_entry(struct super_block *sb,
	u64 addr, u64 value, u8 type)
{
	switch (type) {
		case 1:
			*(u8 *)nova_get_block(sb, addr) = (u8)value;
			break;
		case 2:
			*(u16 *)nova_get_block(sb, addr) = (u16)value;
			break;
		case 4:
			*(u32 *)nova_get_block(sb, addr) = (u32)value;
			break;
		case 8:
			*(u64 *)nova_get_block(sb, addr) = (u64)value;
			break;
		default:
			nova_dbg("%s: unknown data type %u\n",
					__func__, type);
			break;
	}

	nova_flush_buffer((void *)nova_get_block(sb, addr), CACHELINE_SIZE, 0);
}

void nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	int i;

	for (i = 0; i < 4; i++)
		nova_dbg_verbose("Entry %d: addr 0x%llx, value 0x%llx\n",
				i, entry->addrs[i], entry->values[i]);
}

/* Caller needs to grab lite_journal_mutex until commit. */
/* Do not fail, do not sleep. Make it fast! */
u64 nova_create_lite_transaction(struct super_block *sb,
	struct nova_lite_journal_entry *dram_entry1,
	struct nova_lite_journal_entry *dram_entry2,
	int entries)
{
	struct nova_inode *pi;
	struct nova_lite_journal_entry *entry;
	size_t size = sizeof(struct nova_lite_journal_entry);
	u64 new_tail, temp;;

	pi = nova_get_inode_by_ino(sb, NOVA_LITEJOURNAL_INO);
	if (pi->log_head == 0 || pi->log_head != pi->log_tail)
		BUG();

	temp = pi->log_head;
	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);

	nova_print_lite_transaction(dram_entry1);
	memcpy_to_pmem_nocache(entry, dram_entry1, size);

	if (entries == 2) {
		temp = next_lite_journal(temp);
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_print_lite_transaction(dram_entry2);
		memcpy_to_pmem_nocache(entry, dram_entry2, size);
	}

	new_tail = next_lite_journal(temp);
	nova_update_tail(pi, new_tail);
	return new_tail;
}

/* Caller needs to hold lite_journal_mutex until this returns. */
void nova_commit_lite_transaction(struct super_block *sb, u64 tail)
{
	struct nova_inode *pi;

	pi = nova_get_inode_by_ino(sb, NOVA_LITEJOURNAL_INO);
	if (pi->log_tail != tail)
		BUG();

	pi->log_head = tail;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
}

static void nova_undo_lite_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	int i;
	u8 type;

	for (i = 0; i < 4; i++) {
		type = entry->addrs[i] >> 56;
		if (entry->addrs[i] && type) {
			nova_dbg("%s: recover entry %d\n", __func__, i);
			nova_recover_lite_journal_entry(sb, entry->addrs[i],
					entry->values[i], type);
		}
	}
}

static int nova_recover_lite_journal(struct super_block *sb,
	struct nova_inode *pi, int recover)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							pi->log_head);
	nova_undo_lite_journal_entry(sb, entry);

	if (recover == 2) {
		temp = next_lite_journal(pi->log_head);
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_undo_lite_journal_entry(sb, entry);
	}

	nova_update_tail(pi, pi->log_head);
	return 0;
}

int nova_lite_journal_soft_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	u64 temp;

	mutex_init(&sbi->lite_journal_mutex);
	pi = nova_get_inode_by_ino(sb, NOVA_LITEJOURNAL_INO);

	if (pi->log_head == pi->log_tail)
		return 0;

	/* We only allow up to two uncommited entries */
	temp = next_lite_journal(pi->log_head);
	if (pi->log_tail == temp) {
		nova_recover_lite_journal(sb, pi, 1);
		return 0;
	}

	temp = next_lite_journal(temp);
	if (pi->log_tail == temp) {
		nova_recover_lite_journal(sb, pi, 2);
		return 0;
	}

	/* We are in trouble */
	nova_dbg("%s: lite journal head 0x%llx, tail 0x%llx\n",
			__func__, pi->log_head, pi->log_tail);
	return -EINVAL;
}

int nova_lite_journal_hard_init(struct super_block *sb)
{
	struct nova_inode *pi;
	unsigned long blocknr = 0;
	unsigned long nova_ino;
	int allocated;
	u64 block;

	pi = nova_get_inode_by_ino(sb, NOVA_LITEJOURNAL_INO);
	nova_ino = NOVA_LITEJOURNAL_INO;
	allocated = nova_new_log_blocks(sb, nova_ino, &blocknr, 1,
						NOVA_BLOCK_TYPE_4K, 1);
	nova_dbg_verbose("%s: allocate log @ 0x%lx\n", __func__, blocknr);
	if (allocated != 1 || blocknr == 0)
		return -ENOSPC;

	pi->i_blocks = 1;
	block = nova_get_block_off(sb, blocknr,	NOVA_BLOCK_TYPE_4K);
	pi->log_head = pi->log_tail = block;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	return nova_lite_journal_soft_init(sb);
}

