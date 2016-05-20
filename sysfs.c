/*
 * BRIEF DESCRIPTION
 *
 * Proc fs operations
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"

const char *proc_dirname = "fs/NOVA";
static struct proc_dir_entry *nova_proc_root;

void nova_sysfs_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	nova_dbg("%s\n", __func__);
	nova_proc_root = proc_mkdir(proc_dirname, NULL);
	if (nova_proc_root)
		sbi->s_proc = proc_mkdir(sbi->s_bdev->bd_disk->disk_name,
					 nova_proc_root);

	if (sbi->s_proc) {
//		proc_create_data("info", S_IRUGO, journal->j_proc_entry,
//				 &jbd2_seq_info_fops, journal);
	}
}

void nova_sysfs_exit(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	nova_dbg("%s\n", __func__);
	remove_proc_entry(sbi->s_bdev->bd_disk->disk_name, nova_proc_root);
}
