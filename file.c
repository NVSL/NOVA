/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
 *
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
#include "pmfs.h"
#include "dax.h"

static inline int pmfs_can_set_blocksize_hint(struct inode *inode,
	struct pmfs_inode *pi, loff_t new_size)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;

	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (sih->root)
		return 0;
	return 1;
}

int pmfs_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct pmfs_inode *pi, loff_t new_size)
{
	unsigned short block_type;

	if (!pmfs_can_set_blocksize_hint(inode, pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = PMFS_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = PMFS_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = PMFS_BLOCK_TYPE_4K;

hint_set:
	pmfs_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx\n",
		new_size, pi->i_size);
	pmfs_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	pmfs_memunlock_inode(sb, pi);
	pi->i_blk_type = block_type;
	pmfs_memlock_inode(sb, pi);
	return 0;
}

static loff_t pmfs_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	mutex_lock(&inode->i_mutex);
	switch (origin) {
	case SEEK_DATA:
		retval = pmfs_find_region(inode, &offset, 0);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = pmfs_find_region(inode, &offset, 1);
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

int pmfs_is_page_dirty(struct mm_struct *mm, unsigned long address,
	int category, int set_clean)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	int ret = 0;

	if (!mm) {
		pmfs_dbg("%s: mm is NULL\n", __func__);
		return 0;
	}

	if (category == TEST_PAGEALLOC || category == TEST_PAGEZALLOC) {
		return PageDirty((struct page *)address);
	}

	spin_lock(&mm->page_table_lock);

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd)) {
		pmfs_dbg("%s: pgd not found for 0x%lx\n", __func__, address);
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud)) {
		pmfs_dbg("%s: pud not found for 0x%lx\n", __func__, address);
		goto out;
	}

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd)) {
		pmfs_dbg("%s: pmd not found for 0x%lx\n", __func__, address);
		goto out;
	}

	ptep = pte_offset_map(pmd, address);
	if (!pte_present(*ptep)) {
		pmfs_dbg("%s: pte not found for 0x%lx\n", __func__, address);
		goto out;
	}

	if (pte_dirty(*ptep)) {
		pmfs_dbg("%s: page is dirty: 0x%lx\n", __func__, address);
		ret = 1;
		if (set_clean) {
			pte = *ptep;
			pte = pte_mkclean(pte);
			set_pte_at(mm, address, ptep, pte);
			__flush_tlb_one(address);
		}
	} else {
		pmfs_dbg("%s: page is clean: 0x%lx\n", __func__, address);
	}

out:
	spin_unlock(&mm->page_table_lock);
	return ret;
}

static inline int pmfs_set_page_clean(struct mm_struct *mm,
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

static inline int pmfs_check_page_dirty(struct super_block *sb,
	struct mem_addr *pair)
{
	int ret;

	if (pmfs_has_page_cache(sb)) {
		ret = IS_DIRTY(pair->dram) || IS_MAPPED(pair->dram);
	} else {
//		u64 nvmm_block;
//		unsigned long nvmm_addr;

		if (pair->nvmm_mmap == 0)
			return 0;

//		nvmm_block = pair->nvmm_mmap << PAGE_SHIFT;
//		nvmm_addr = (unsigned long)pmfs_get_block(sb, nvmm_block);
//		ret = pmfs_is_page_dirty(&init_mm, nvmm_addr, TEST_NVMM, 1);
		ret = pair->nvmm_mmap_write;
	}

	return ret;
}

static unsigned long pmfs_get_dirty_range(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_inode_info *si, loff_t *start,
	loff_t end)
{
	struct mem_addr *pair = NULL;
	unsigned long flush_bytes = 0, bytes;
	pgoff_t pgoff;
	loff_t offset;
	loff_t dirty_start;
	loff_t temp = *start;

	dirty_start = temp;
	while (temp < end) {
		pgoff = temp >> PAGE_CACHE_SHIFT;
		offset = temp & ~PAGE_CACHE_MASK;
		bytes = sb->s_blocksize - offset;
		if (bytes > (end - temp))
			bytes = end - temp;

		pair = pmfs_get_mem_pair(sb, pi, si, pgoff);
		if (pair) {
			if (pmfs_check_page_dirty(sb, pair)) {
				if (flush_bytes == 0)
					dirty_start = temp;
				flush_bytes += bytes;
				atomic64_inc(&fsync_pages);
			} else {
				if (flush_bytes)
					break;
			}
		}
		temp += bytes;
	}

	if (flush_bytes == 0)
		*start = end;
	else
		*start = dirty_start;

	return flush_bytes;
}

static void pmfs_update_dirty_range(struct pmfs_inode_info *si,
	loff_t start, loff_t end)
{
	u64 low;
	u64 high;

	if (si->low_dirty > si->high_dirty)
		return;

	low = si->low_dirty << PAGE_SHIFT;
	high = (si->high_dirty + 1) << PAGE_SHIFT;

	if (start <= low && end >= high) {
		si->low_dirty = ULONG_MAX;
		si->high_dirty = 0;
	} else if (start <= low && end > low) {
		si->low_dirty = end >> PAGE_SHIFT;
	} else if (end >= high && start < high) {
		si->high_dirty = start >> PAGE_SHIFT ;
	}
}

static void pmfs_get_sync_range(struct pmfs_inode_info *si, int mmaped,
	loff_t *start, loff_t *end)
{
	unsigned long start_blk, end_blk;
	unsigned long low_blk, high_blk;

	start_blk = *start >> PAGE_SHIFT;
	end_blk = *end >> PAGE_SHIFT;

	low_blk = si->low_dirty;
	high_blk = si->high_dirty;
	if (mmaped && si->low_mmap < low_blk)
		low_blk = si->low_mmap;
	if (mmaped && si->high_mmap > high_blk)
		high_blk = si->high_mmap;

	if (start_blk < low_blk)
		*start = low_blk << PAGE_SHIFT;
	if (end_blk > high_blk)
		*end = (high_blk + 1) << PAGE_SHIFT;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling pmfs_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * pmfs_flush_buffer() on fsync() */
int pmfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	unsigned long start_blk, end_blk;
	u64 end_tail = 0, begin_tail = 0;
	u64 begin_temp = 0, end_temp = 0;
	int ret = 0;
	int mmaped = 0;
	loff_t sync_start, sync_end;
	loff_t isize;
	timing_t fsync_time;

	PMFS_START_TIMING(fsync_t, fsync_time);
	if (mapping_mapped(mapping))
		mmaped = 1;

	if (!pmfs_has_page_cache(sb) && mmaped == 0)
		goto out;

	mutex_lock(&inode->i_mutex);

	/* Check the dirty range */
	pi = pmfs_get_inode(sb, inode);
	if (mmaped == 0 && si->low_dirty > si->high_dirty) {
		mutex_unlock(&inode->i_mutex);
		goto out;
	}

	end += 1; /* end is inclusive. We like our indices normal please! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		pmfs_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		PMFS_END_TIMING(fsync_t, fsync_time);
		mutex_unlock(&inode->i_mutex);
		return 0;
	}

	pmfs_get_sync_range(si, mmaped, &start, &end);
	start_blk = start >> PAGE_SHIFT;
	end_blk = end >> PAGE_SHIFT;

	pmfs_dbgv("%s: mmaped %d, start %llu, end %llu, size %llu, "
			" start_blk %lu, end_blk %lu\n",
			__func__, mmaped, start, end, isize, start_blk,
			end_blk);

	sync_start = start;
	sync_end = end;
	end_temp = pi->log_tail;

	do {
		unsigned long nr_flush_bytes = 0;

		nr_flush_bytes = pmfs_get_dirty_range(sb, pi, si, &start, end);

		pmfs_dbgv("start %llu, flush bytes %lu\n",
				start, nr_flush_bytes);
		if (nr_flush_bytes) {
			pmfs_copy_to_nvmm(sb, inode, pi, start,
				nr_flush_bytes, &begin_temp, &end_temp);
			if (begin_tail == 0)
				begin_tail = begin_temp;
		}

		start += nr_flush_bytes;
	} while (start < end);

	if (pmfs_has_page_cache(sb))
		pmfs_update_dirty_range(si, sync_start, sync_end);

	end_tail = end_temp;
	if (begin_tail && end_tail && end_tail != pi->log_tail) {
		pmfs_update_tail(pi, end_tail);

		/* Free the overlap blocks after the write is committed */
		ret = pmfs_reassign_file_btree(sb, pi, sih, begin_tail);

		inode->i_blocks = le64_to_cpu(pi->i_blocks);
	}

	mutex_unlock(&inode->i_mutex);

out:
	PMFS_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int pmfs_flush(struct file *file, fl_owner_t id)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	loff_t isize, start, end;
	int ret = 0;

	/* if the file was opened for writing, make it persistent.
	 * Only sync the dirty range. Mmap needs to call msync() explicitly.
	 */
	isize = i_size_read(inode);
	if (si->low_dirty <= si->high_dirty) {
		start = si->low_dirty << PAGE_SHIFT;
		end = (si->high_dirty + 1) << PAGE_SHIFT;
		if (end > isize)
			end = isize;
		pmfs_fsync(file, start, end, 1);
	}

	return ret;
}

static int pmfs_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

static unsigned long
pmfs_get_unmapped_area(struct file *file, unsigned long addr,
			unsigned long len, unsigned long pgoff,
			unsigned long flags)
{
	unsigned long align_size;
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	struct inode *inode = file->f_mapping->host;
	struct pmfs_inode *pi = pmfs_get_inode(inode->i_sb, inode);
	struct vm_unmapped_area_info info;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (pi->i_blk_type == PMFS_BLOCK_TYPE_1G)
		align_size = PUD_SIZE;
	else if (pi->i_blk_type == PMFS_BLOCK_TYPE_2M)
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

const struct file_operations pmfs_dax_file_operations = {
	.llseek			= pmfs_llseek,
	.read			= pmfs_dax_file_read,
	.write			= pmfs_dax_file_write,
//	.write			= pmfs_cow_file_write,
//	.aio_read		= dax_file_aio_read,
//	.aio_write		= dax_file_aio_write,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.mmap			= pmfs_dax_file_mmap,
	.open			= pmfs_open,
	.fsync			= pmfs_fsync,
	.flush			= pmfs_flush,
	.get_unmapped_area	= pmfs_get_unmapped_area,
	.unlocked_ioctl		= pmfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= pmfs_compat_ioctl,
#endif
};

const struct inode_operations pmfs_file_inode_operations = {
	.setattr	= pmfs_notify_change,
	.getattr	= pmfs_getattr,
	.get_acl	= NULL,
};
