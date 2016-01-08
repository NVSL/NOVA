/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
 *
 * Copyright 2015 NVSL, UC San Diego
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "nova.h"

static inline int nova_can_set_blocksize_hint(struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (sih->i_size > 0)
		return 0;
	return 1;
}

int nova_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	unsigned short block_type;

	if (!nova_can_set_blocksize_hint(inode, pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = NOVA_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = NOVA_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = NOVA_BLOCK_TYPE_4K;

hint_set:
	nova_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx\n",
		new_size, pi->i_size);
	nova_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	nova_memunlock_inode(sb, pi);
	pi->i_blk_type = block_type;
	nova_memlock_inode(sb, pi);
	return 0;
}

static loff_t nova_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	mutex_lock(&inode->i_mutex);
	switch (origin) {
	case SEEK_DATA:
		retval = nova_find_region(inode, &offset, 0);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = nova_find_region(inode, &offset, 1);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		mutex_unlock(&inode->i_mutex);
		return -EINVAL;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	mutex_unlock(&inode->i_mutex);
	return offset;
}

#if 0
int nova_is_page_dirty(struct mm_struct *mm, unsigned long address,
	int category, int set_clean)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	int ret = 0;

	if (!mm) {
		nova_dbg("%s: mm is NULL\n", __func__);
		return 0;
	}

	spin_lock(&mm->page_table_lock);

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd)) {
		nova_dbg("%s: pgd not found for 0x%lx\n", __func__, address);
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud)) {
		nova_dbg("%s: pud not found for 0x%lx\n", __func__, address);
		goto out;
	}

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd)) {
		nova_dbg("%s: pmd not found for 0x%lx\n", __func__, address);
		goto out;
	}

	ptep = pte_offset_map(pmd, address);
	if (!pte_present(*ptep)) {
		nova_dbg("%s: pte not found for 0x%lx\n", __func__, address);
		goto out;
	}

	if (pte_dirty(*ptep)) {
		nova_dbg("%s: page is dirty: 0x%lx\n", __func__, address);
		ret = 1;
		if (set_clean) {
			pte = *ptep;
			pte = pte_mkclean(pte);
			set_pte_at(mm, address, ptep, pte);
			__flush_tlb_one(address);
		}
	} else {
		nova_dbg("%s: page is clean: 0x%lx\n", __func__, address);
	}

out:
	spin_unlock(&mm->page_table_lock);
	return ret;
}

static inline int nova_set_page_clean(struct mm_struct *mm,
	unsigned long address, pte_t *ptep)
{
	pte_t pte;

	spin_lock(&mm->page_table_lock);
	pte = *ptep;
	pte = pte_mkclean(pte);
	set_pte_at(mm, address, ptep, pte);
	spin_unlock(&mm->page_table_lock);

	return 0;
}
#endif

static inline int nova_check_page_dirty(struct super_block *sb,
	unsigned long addr)
{
	return IS_MAP_WRITE(addr);
}

static unsigned long nova_get_dirty_range(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info *si, loff_t *start,
	loff_t end)
{
	unsigned long flush_bytes = 0;
	unsigned long bytes;
	unsigned long cache_addr = 0;
	pgoff_t pgoff;
	loff_t offset;
	loff_t dirty_start;
	loff_t temp = *start;

	nova_dbgv("%s: inode %llu, start %llu, end %llu\n",
			__func__, pi->nova_ino, *start, end);

	dirty_start = temp;
	while (temp < end) {
		pgoff = temp >> PAGE_CACHE_SHIFT;
		offset = temp & ~PAGE_CACHE_MASK;
		bytes = sb->s_blocksize - offset;
		if (bytes > (end - temp))
			bytes = end - temp;

		cache_addr = nova_get_cache_addr(sb, si, pgoff);
		if (cache_addr && nova_check_page_dirty(sb, cache_addr)) {
			if (flush_bytes == 0)
				dirty_start = temp;
			flush_bytes += bytes;
			fsync_pages++;
		} else {
			if (flush_bytes)
				break;
		}
		temp += bytes;
	}

	if (flush_bytes == 0)
		*start = end;
	else
		*start = dirty_start;

	return flush_bytes;
}

static void nova_get_sync_range(struct nova_inode_info_header *sih,
	loff_t *start, loff_t *end)
{
	unsigned long start_blk, end_blk;
	unsigned long low_blk, high_blk;

	start_blk = *start >> PAGE_SHIFT;
	end_blk = *end >> PAGE_SHIFT;

	low_blk = sih->low_mmap;
	high_blk = sih->high_mmap;

	if (start_blk < low_blk)
		*start = low_blk << PAGE_SHIFT;
	if (end_blk > high_blk)
		*end = (high_blk + 1) << PAGE_SHIFT;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync() */
int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	unsigned long start_blk, end_blk;
	u64 end_tail = 0, begin_tail = 0;
	u64 begin_temp = 0, end_temp = 0;
	int ret = 0;
	loff_t sync_start, sync_end;
	loff_t isize;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);
	if (!mapping_mapped(mapping))
		goto out;

	mutex_lock(&inode->i_mutex);

	/* Check the dirty range */
	pi = nova_get_inode(sb, inode);

	end += 1; /* end is inclusive. We like our indices normal please! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		nova_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		NOVA_END_TIMING(fsync_t, fsync_time);
		mutex_unlock(&inode->i_mutex);
		return 0;
	}

	nova_get_sync_range(sih, &start, &end);
	start_blk = start >> PAGE_SHIFT;
	end_blk = end >> PAGE_SHIFT;

	nova_dbgv("%s: start %llu, end %llu, size %llu, "
			" start_blk %lu, end_blk %lu\n",
			__func__, start, end, isize, start_blk,
			end_blk);

	sync_start = start;
	sync_end = end;
	end_temp = pi->log_tail;

	do {
		unsigned long nr_flush_bytes = 0;

		nr_flush_bytes = nova_get_dirty_range(sb, pi, si, &start, end);

		nova_dbgv("start %llu, flush bytes %lu\n",
				start, nr_flush_bytes);
		if (nr_flush_bytes) {
			nova_copy_to_nvmm(sb, inode, pi, start,
				nr_flush_bytes, &begin_temp, &end_temp);
			if (begin_tail == 0)
				begin_tail = begin_temp;
		}

		start += nr_flush_bytes;
	} while (start < end);

	end_tail = end_temp;
	if (begin_tail && end_tail && end_tail != pi->log_tail) {
		nova_update_tail(pi, end_tail);

		/* Free the overlap blocks after the write is committed */
		ret = nova_reassign_file_btree(sb, pi, sih, begin_tail);

		inode->i_blocks = le64_to_cpu(pi->i_blocks);
	}

	mutex_unlock(&inode->i_mutex);

out:
	NOVA_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int nova_flush(struct file *file, fl_owner_t id)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;

	 /* Issue a msync() on close */
	if (mapping_mapped(mapping))
		nova_fsync(file, 0, i_size_read(inode), 0);

	return 0;
}

static int nova_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

#if 0
static unsigned long
nova_get_unmapped_area(struct file *file, unsigned long addr,
			unsigned long len, unsigned long pgoff,
			unsigned long flags)
{
	unsigned long align_size;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct inode *inode = file->f_mapping->host;
	struct nova_inode *pi = nova_get_inode(inode->i_sb, inode);
	struct vm_unmapped_area_info info;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (pi->i_blk_type == NOVA_BLOCK_TYPE_1G)
		align_size = PUD_SIZE;
	else if (pi->i_blk_type == NOVA_BLOCK_TYPE_2M)
		align_size = PMD_SIZE;
	else
		align_size = PAGE_SIZE;

	if (flags & MAP_FIXED) {
		/* FIXME: We could use 4K mappings as fallback. */
		if (len & (align_size - 1))
			return -EINVAL;
		if (addr & (align_size - 1))
			return -EINVAL;
		return addr;
	}

	if (addr) {
		addr = ALIGN(addr, align_size);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/*
	 * FIXME: Using the following values for low_limit and high_limit
	 * implicitly disables ASLR. Awaiting a better way to have this fixed.
	 */
	info.flags = 0;
	info.length = len;
	info.low_limit = TASK_UNMAPPED_BASE;
	info.high_limit = TASK_SIZE;
	info.align_mask = align_size - 1;
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}
#endif

const struct file_operations nova_dax_file_operations = {
	.llseek			= nova_llseek,
	.read			= nova_dax_file_read,
	.write			= nova_dax_file_write,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.mmap			= nova_dax_file_mmap,
	.open			= nova_open,
	.fsync			= nova_fsync,
	.flush			= nova_flush,
//	.get_unmapped_area	= nova_get_unmapped_area,
	.unlocked_ioctl		= nova_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= nova_compat_ioctl,
#endif
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};
