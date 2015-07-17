/*
 * BRIEF DESCRIPTION
 *
 * DAX operations.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

ssize_t pmfs_dax_file_read(struct file *filp, char __user *buf, size_t len,
			    loff_t *ppos);
ssize_t pmfs_dax_file_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *ppos);
int pmfs_dax_file_mmap(struct file *file, struct vm_area_struct *vma);
