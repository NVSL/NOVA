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

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "pmfs.h"
#include "xip.h"

static inline int pmfs_can_set_blocksize_hint(struct pmfs_inode *pi,
					       loff_t new_size)
{
	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (le64_to_cpu(pi->root))
		return 0;
	return 1;
}

int pmfs_set_blocksize_hint(struct super_block *sb, struct pmfs_inode *pi,
		loff_t new_size)
{
	unsigned short block_type;

	if (!pmfs_can_set_blocksize_hint(pi, new_size))
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
		"Hint: new_size 0x%llx, i_size 0x%llx, root 0x%llx\n",
		new_size, pi->i_size, le64_to_cpu(pi->root));
	pmfs_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	pmfs_memunlock_inode(sb, pi);
	pi->i_blk_type = block_type;
	pmfs_memlock_inode(sb, pi);
	return 0;
}

/*
 * We do not suppoer fallocate as pre-allocation does not make sense
 * for a copy-on-write file system.
 */
#if 0
static long pmfs_fallocate(struct file *file, int mode, loff_t offset,
			    loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	long ret = 0;
	unsigned long blocknr, blockoff;
	int num_blocks, blocksize_mask;
	struct pmfs_inode *pi;
	pmfs_transaction_t *trans;
	loff_t new_size;

	pmfs_dbg_verbose("%s: inode %lu, offset %lld, len %lld\n",
			__func__, inode->i_ino, offset, len);
	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	mutex_lock(&inode->i_mutex);

	new_size = len + offset;
	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			goto out;
	}

	pi = pmfs_get_inode(sb, inode->i_ino);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}
	trans = pmfs_new_transaction(sb, MAX_INODE_LENTRIES +
			MAX_METABLOCK_LENTRIES);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}
	pmfs_add_logentry(sb, trans, pi, MAX_DATA_PER_LENTRY, LE_DATA);

	/* Set the block size hint */
	pmfs_set_blocksize_hint(sb, pi, new_size);

	blocksize_mask = sb->s_blocksize - 1;
	blocknr = offset >> sb->s_blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sb->s_blocksize_bits;

	/* FIXME */
	ret = pmfs_alloc_blocks(trans, inode, blocknr, num_blocks, true);

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;

	pmfs_memunlock_inode(sb, pi);
	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		pi->i_flags |= cpu_to_le32(PMFS_EOFBLOCKS_FL);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		inode->i_size = new_size;
		pi->i_size = cpu_to_le64(inode->i_size);
	}
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pmfs_memlock_inode(sb, pi);

	pmfs_commit_transaction(sb, trans);

out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}
#endif

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

int pmfs_is_page_dirty(unsigned long address, pte_t **ptep)
{
	struct mm_struct *mm = current->mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret = 0;

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

	pte = pte_offset_map(pmd, address);
	if (!pte_present(*pte)) {
		pmfs_dbg("%s: pte not found for 0x%lx\n", __func__, address);
		goto out;
	}

	if (pte_dirty(*pte)) {
		pmfs_dbg("%s: page is dirty: 0x%lx\n", __func__, address);
		ret = 1;
	} else {
		pmfs_dbg("%s: page is clean: 0x%lx\n", __func__, address);
	}

	*ptep = pte;
out:
	spin_unlock(&mm->page_table_lock);
	return ret;
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
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	unsigned long start_blk, end_blk;
	loff_t isize;
	timing_t fsync_time;

	PMFS_START_TIMING(fsync_t, fsync_time);
	/* if the file is not mmap'ed, there is no need to do clflushes */
//	if (mapping_mapped(mapping) == 0)
//		goto persist;

	/* Check the dirty range */
	pi = pmfs_get_inode(sb, inode->i_ino);
	if (si->low_dirty > si->high_dirty)
		goto persist;

	end += 1; /* end is inclusive. We like our indices normal please ! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		pmfs_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		PMFS_END_TIMING(fsync_t, fsync_time);
		return 0;
	}

	/* Align start to cacheline boundaries */
	start = start & CACHELINE_MASK;
//	end = CACHELINE_ALIGN(end);

	start_blk = start >> PAGE_SHIFT;
	if (start_blk < si->low_dirty) {
		start = si->low_dirty << PAGE_SHIFT;
		start_blk = si->low_dirty;
	}
	end_blk = end >> PAGE_SHIFT;
	if (end_blk > si->high_dirty) {
		end = (si->high_dirty + 1) << PAGE_SHIFT;
		end_blk = si->high_dirty;
	}
	pmfs_dbg_verbose("%s: start_blk %lu, end_blk %lu\n",
				__func__, start_blk, end_blk);

	do {
		u64 page = 0;
//		void *xip_mem;
		pgoff_t pgoff;
		loff_t offset;
		unsigned long nr_flush_bytes;

		pgoff = start >> PAGE_CACHE_SHIFT;
		offset = start & ~PAGE_CACHE_MASK;

		nr_flush_bytes = PAGE_CACHE_SIZE - offset;
		if (nr_flush_bytes > (end - start))
			nr_flush_bytes = end - start;
		if (nr_flush_bytes == 0)
			nr_flush_bytes = PAGE_SIZE;

		page = pmfs_find_data_block(inode, (sector_t)pgoff, false);
		pmfs_dbg_verbose("pgoff %lu: page 0x%llx\n", pgoff, page);
		if (page && IS_DIRTY(page)) {
			pmfs_dbg_verbose("fsync: pgoff %lu, "
					"page 0x%llx dirty\n", pgoff, page);
			pmfs_copy_to_nvmm(inode, pgoff, offset,
						nr_flush_bytes);
		}
		start += nr_flush_bytes;
	} while (start < end);

	if (start_blk == si->low_dirty && end_blk == si->high_dirty) {
		si->low_dirty = MAX_BLOCK;
		si->high_dirty = 0;
	} else if (start_blk == si->low_dirty) {
		si->low_dirty = (start_blk == MAX_BLOCK ?
					MAX_BLOCK : start_blk + 1);
	} else if (end_blk == si->high_dirty) {
		si->high_dirty = (end_blk == 0 ? 0 : end_blk - 1);
	}

persist:
	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	PMFS_END_TIMING(fsync_t, fsync_time);
	return 0;
}

/* This callback is called when a file is closed */
static int pmfs_flush(struct file *file, fl_owner_t id)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	loff_t isize;
	int ret = 0;
	/* if the file was opened for writing, make it persistent.
	 * TODO: Should we be more smart to check if the file was modified? */

	isize = i_size_read(inode);
	pmfs_fsync(file, 0, isize, 1);

	if (file->f_mode & FMODE_WRITE) {
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
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
	struct pmfs_inode *pi = pmfs_get_inode(inode->i_sb, inode->i_ino);
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

const struct file_operations pmfs_xip_file_operations = {
	.llseek			= pmfs_llseek,
	.read			= pmfs_xip_file_read,
	.write			= pmfs_xip_file_write,
//	.write			= pmfs_cow_file_write,
//	.aio_read		= xip_file_aio_read,
//	.aio_write		= xip_file_aio_write,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.mmap			= pmfs_xip_file_mmap,
	.open			= pmfs_open,
	.fsync			= pmfs_fsync,
	.flush			= pmfs_flush,
	.get_unmapped_area	= pmfs_get_unmapped_area,
	.unlocked_ioctl		= pmfs_ioctl,
//	.fallocate		= pmfs_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= pmfs_compat_ioctl,
#endif
};

const struct inode_operations pmfs_file_inode_operations = {
	.setattr	= pmfs_notify_change,
	.getattr	= pmfs_getattr,
	.get_acl	= NULL,
};
