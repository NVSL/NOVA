/*
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
#ifndef __PMFS_JOURNAL_H__
#define __PMFS_JOURNAL_H__
#include <linux/slab.h>

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)

/* Lite journal */
struct pmfs_lite_journal_entry {
	/* The highest byte of addr is type */
	u64 addrs[4];
	u64 values[4];
};

int pmfs_lite_journal_soft_init(struct super_block *sb);
int pmfs_lite_journal_hard_init(struct super_block *sb);
u64 pmfs_create_lite_transaction(struct super_block *sb,
	struct pmfs_lite_journal_entry *dram_entry1,
	struct pmfs_lite_journal_entry *dram_entry2,
	int entries);
void pmfs_commit_lite_transaction(struct super_block *sb, u64 tail);
#endif    /* __PMFS_JOURNAL_H__ */
