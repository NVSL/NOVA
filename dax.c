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

#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include "pmfs.h"
#include "dax.h"

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi = pmfs_get_inode(sb, inode);
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_file_write_entry *entry;
	struct mem_addr *pair;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;

	pos = *ppos;
	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ~PAGE_CACHE_MASK;

	if (!access_ok(VERIFY_WRITE, buf, len)) {
		error = -EFAULT;
		goto out;
	}

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	pmfs_dbg_verbose("%s: inode %lu, block %llu, offset %lu, count %lu, "
		"size %lld\n", __func__, inode->i_ino,
		pos >> sb->s_blocksize_bits, offset, len, isize);

	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	do {
		unsigned long nr, left;
		unsigned long addr = 0;
		void *dax_mem = NULL;
		int zero = 0;
		int dram_copy = 0;

		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}

		pair = pmfs_get_mem_pair(sb, pi, si, index);
		if (unlikely(pair == NULL)) {
			pmfs_dbg("Required extent not found: pgoff %lu, "
				"inode size %lld\n", index, isize);
			nr = PAGE_SIZE;
			zero = 1;
			goto memcpy;
		}

		if (pmfs_has_page_cache(sb)) {
			addr = pmfs_get_dram_addr(pair);
			if (addr) {
				nr = PAGE_SIZE;
				dax_mem = (void *)DRAM_ADDR(addr);
				pmfs_dbgv("%s: memory @ 0x%lx\n", __func__,
						(unsigned long)dax_mem);
				if (unlikely(OUTDATE(pair->dram))) {
					pmfs_dbg("%s: inode %lu DRAM page %lu "
						"is out-of-date\n", __func__,
						inode->i_ino, index);
				} else if (unlikely(UNINIT(pair->dram))) {
					pmfs_dbg("%s: inode %lu DRAM page %lu "
						"is unitialized\n", __func__,
						inode->i_ino, index);
				} else {
					dram_copy = 1;
					goto memcpy;
				}
			}
		}

		/* Find contiguous blocks */
		entry = (struct pmfs_file_write_entry *)
				pmfs_get_block(sb, pair->nvmm_entry);
		if (entry == NULL) {
			pmfs_dbg("%s: entry is NULL\n", __func__);
			return -EINVAL;
		}
		if (index < entry->pgoff ||
			index - entry->pgoff >= entry->num_pages) {
			pmfs_err(sb, "%s ERROR: %lu, entry pgoff %u, num %u, "
				"blocknr %llu\n", __func__, index, entry->pgoff,
				entry->num_pages, entry->block >> PAGE_SHIFT);
			return -EINVAL;
		}
		if (entry->invalid_pages == 0) {
			nr = (entry->num_pages - (index - entry->pgoff))
				* PAGE_SIZE;
		} else {
			nr = PAGE_SIZE;
		}

		if (pair->nvmm == 0) {
			pmfs_dbg("%s: entry nvmm is NULL\n", __func__);
			return -EINVAL;
		}
		dax_mem = pmfs_get_block(sb, (pair->nvmm << PAGE_SHIFT));

memcpy:
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		if (dram_copy) {
			PMFS_START_TIMING(memcpy_r_dram_t, memcpy_time);
		} else {
			PMFS_START_TIMING(memcpy_r_nvmm_t, memcpy_time);
		}

		if (!zero)
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		if (dram_copy) {
			PMFS_END_TIMING(memcpy_r_dram_t, memcpy_time);
		} else {
			PMFS_END_TIMING(memcpy_r_nvmm_t, memcpy_time);
		}

		if (pmfs_has_page_cache(sb)) {
			if (pair && pair->page)
				kunmap_atomic(dax_mem);
		}

		if (left) {
			pmfs_dbg("%s ERROR!: bytes %lu, left %lu\n",
				__func__, nr, left);
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	read_bytes += copied;
	pmfs_dbgv("%s returned %zu\n", __func__, copied);
	return (copied ? copied : error);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * i_mutex.
 */
ssize_t pmfs_dax_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t dax_read_time;

	PMFS_START_TIMING(dax_read_t, dax_read_time);
//	rcu_read_lock();
	res = do_dax_mapping_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	PMFS_END_TIMING(dax_read_t, dax_read_time);
	return res;
}

static inline int pmfs_copy_partial_block(struct super_block *sb,
	struct mem_addr *pair, unsigned long index,
	size_t offset, void* kmem, bool is_end_blk)
{
	void *ptr;

	/* Copy from dram page cache, otherwise from nvmm */
	if (pair->page) {
		ptr = kmap_atomic(pair->page);
	} else if (pair->dram) {
		ptr = (void *)DRAM_ADDR(pair->dram);
	} else {
		ptr = pmfs_get_block(sb, (pair->nvmm << PAGE_SHIFT));
	}
	if (ptr != NULL) {
		if (is_end_blk)
			memcpy(kmem + offset, ptr + offset,
				sb->s_blocksize - offset);
		else 
			memcpy(kmem, ptr, offset);
	}

	if (pair->page)
		kunmap_atomic(ptr);

	return 0;
}

/* 
 * Fill the new start/end block from original blocks.
 * Do nothing if fully covered; copy if original blocks present;
 * Fill zero otherwise.
 */
static void pmfs_handle_head_tail_blocks(struct super_block *sb,
	struct pmfs_inode *pi, struct inode *inode, loff_t pos, size_t count,
	void *kmem)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	size_t offset, eblk_offset;
	unsigned long start_blk, end_blk, num_blocks;
	unsigned long file_end_blk;
	struct mem_addr *pair;
	timing_t partial_time;

	PMFS_START_TIMING(partial_block_t, partial_time);
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (pmfs_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	file_end_blk = inode->i_size >> PAGE_SHIFT;
	if (start_blk > file_end_blk) {
		PMFS_END_TIMING(partial_block_t, partial_time);
		return;
	}

	pmfs_dbg_verbose("%s: %lu blocks\n", __func__, num_blocks);
	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	pmfs_dbg_verbose("%s: start offset %lu start blk %lu %p\n", __func__,
				offset, start_blk, kmem);
	if (offset != 0) {
		pair = pmfs_get_mem_pair(sb, pi, si, start_blk);
		if (pair == NULL) {
			/* Fill zero */
		    	memset(kmem, 0, offset);
		} else {
			/* Copy from original block */
			pmfs_copy_partial_block(sb, pair, start_blk,
					offset, kmem, false);
		}
		pmfs_flush_buffer(kmem, offset, 0);
	}

	if (pos + count >= inode->i_size) {
		PMFS_END_TIMING(partial_block_t, partial_time);
		return;
	}

	kmem = (void *)((char *)kmem +
			((num_blocks - 1) << sb->s_blocksize_bits));
	eblk_offset = (pos + count) & (pmfs_inode_blk_size(pi) - 1);
	pmfs_dbg_verbose("%s: end offset %lu, end blk %lu %p\n", __func__,
				eblk_offset, end_blk, kmem);
	if (eblk_offset != 0) {
		pair = pmfs_get_mem_pair(sb, pi, si, start_blk);
		if (pair == NULL) {
			/* Fill zero */
		    	memset(kmem + eblk_offset, 0,
					sb->s_blocksize - eblk_offset);
		} else {
			/* Copy from original block */
			pmfs_copy_partial_block(sb, pair, start_blk,
					eblk_offset, kmem, true);
		}
		pmfs_flush_buffer(kmem + eblk_offset,
					sb->s_blocksize - eblk_offset, 0);
	}

	PMFS_END_TIMING(partial_block_t, partial_time);
}

static inline size_t pmfs_memcpy_to_nvmm(char *kmem, loff_t offset,
	const char *buf, size_t bytes)
{
	size_t copied = 0;

	if (support_clwb) {
		copied = bytes - __copy_from_user(kmem + offset, buf, bytes);
		pmfs_flush_buffer(kmem + offset, copied, 0);
	} else {
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
	}

	return copied;
}

int pmfs_reassign_file_btree(struct super_block *sb,
	struct pmfs_inode *pi, struct pmfs_inode_info_header *sih,
	u64 begin_tail)
{
	struct pmfs_file_write_entry *entry_data;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct pmfs_file_write_entry);

	while (curr_p != pi->log_tail) {
		if (is_last_entry(curr_p, entry_size, 0))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			pmfs_err(sb, "%s: File inode %llu log is NULL!\n",
				__func__, pi->pmfs_ino);
			return -EINVAL;
		}

		entry_data = (struct pmfs_file_write_entry *)
					pmfs_get_block(sb, curr_p);

		if (pmfs_get_entry_type(entry_data) != FILE_WRITE) {
			pmfs_dbg("%s: entry type is not write? %d\n",
				__func__, pmfs_get_entry_type(entry_data));
			curr_p += entry_size;
			continue;
		}

		pmfs_assign_blocks(sb, pi, sih, entry_data, NULL,
					curr_p, true, true, false);
		curr_p += entry_size;
	}

	return 0;
}

ssize_t pmfs_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos, bool need_mutex)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	struct pmfs_file_write_entry entry_data;
	ssize_t     written = 0;
	loff_t pos;
	size_t count, offset, copied, ret;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	int allocated;
	void* kmem;
	u64 curr_entry;
	size_t bytes;
	long status = 0;
	timing_t cow_write_time, memcpy_time;
	unsigned long step = 0;
	u64 temp_tail, begin_tail = 0;
	u32 time;

	PMFS_START_TIMING(cow_write_t, cow_write_time);

	sb_start_write(inode->i_sb);
	if (need_mutex)
		mutex_lock(&inode->i_mutex);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;
	count = len;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,9)
	ret = generic_write_checks(filp, &pos, &count, S_ISBLK(inode->i_mode));
	if (ret || count == 0)
		goto out;
#endif

	pi = pmfs_get_inode(sb, inode);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	/* offset in the actual block size block */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,1,0)
	ret = file_remove_suid(filp);
#else
	ret = file_remove_privs(filp);
#endif
	if (ret) {
		goto out;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	pmfs_dbg_verbose("%s: inode %lu, block %llu, offset %lu, count %lu\n",
			__func__, inode->i_ino,	pos >> sb->s_blocksize_bits,
			offset, count);

	temp_tail = pi->log_tail;
	while (num_blocks > 0) {
		offset = pos & (pmfs_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		/* don't zero-out the allocated blocks */
		allocated = pmfs_new_data_blocks(sb, pi, &blocknr, num_blocks,
					start_blk, pi->i_blk_type, 0, 1);
		pmfs_dbg_verbose("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			pmfs_err(sb, "%s alloc blocks failed!, %d\n", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = pmfs_get_block(inode->i_sb,
			pmfs_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0)
			pmfs_handle_head_tail_blocks(sb, pi, inode, pos, bytes,
								kmem);

		/* Now copy from user buf */
//		pmfs_dbg("Write: %p\n", kmem);
		PMFS_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = pmfs_memcpy_to_nvmm((char *)kmem, offset, buf, bytes);
		PMFS_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		entry_data.pgoff = cpu_to_le32(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(pmfs_get_block_off(sb, blocknr,
							pi->i_blk_type));
		entry_data.mtime = cpu_to_le32(time);
		/* Set entry type after set block */
		pmfs_set_entry_type((void *)&entry_data, FILE_WRITE);

		if (pos + copied > inode->i_size)
			entry_data.size = cpu_to_le64(pos + copied);
		else
			entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = pmfs_append_file_write_entry(sb, pi, inode,
							&entry_data, temp_tail);
		if (curr_entry == 0) {
			pmfs_err(sb, "ERROR: append inode entry failed\n");
			ret = -EINVAL;
			goto out;
		}

		pmfs_dbgv("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			pmfs_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct pmfs_file_write_entry);
	}

	pmfs_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
			(total_blocks << (data_bits - sb->s_blocksize_bits)));
	pmfs_memlock_inode(sb, pi);

	pmfs_update_tail(pi, temp_tail);

	/* Free the overlap blocks after the write is committed */
	ret = pmfs_reassign_file_btree(sb, pi, sih, begin_tail);
	if (ret)
		goto out;

	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	ret = written;
	write_breaks += step;
//	pmfs_dbg("blocks: %lu, %llu\n", inode->i_blocks, pi->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

out:
	if (need_mutex)
		mutex_unlock(&inode->i_mutex);
	sb_end_write(inode->i_sb);
	PMFS_END_TIMING(cow_write_t, cow_write_time);
	cow_write_bytes += written;
	return ret;
}

/* Handle partial and unitialized dram page */
static void pmfs_preprocess_dram_block(struct super_block *sb,
	struct pmfs_inode_info *si, struct mem_addr *pair, void *kmem,
	unsigned long start_blk, size_t offset, size_t tail)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);
	u64 bp;
	void *nvmm;

	/* If only NVMM page presents, copy the partial block */
	if ((OUTDATE(pair->dram)) && (offset || tail)) {
		bp = __pmfs_find_nvmm_block(sb, si, pair, start_blk);
		nvmm = pmfs_get_block(sb, bp);
		memcpy(kmem, nvmm, PAGE_SIZE);
		pair->dram &= ~UNINIT_BIT;
	}

	/* If DRAM is uninitialized, memset the partial block to 0 */
	if ((UNINIT(pair->dram)) && (offset || tail)) {
		if (offset)
			memcpy(kmem, (void *)DRAM_ADDR(sbi->zeroed_page),
					offset);
		if (tail)
			memcpy(kmem + tail,
				(void *)DRAM_ADDR(sbi->zeroed_page),
				PAGE_SIZE - tail);
	}
}

static void pmfs_postprocess_dram_block(struct super_block *sb,
	struct pmfs_inode_info *si, struct mem_addr *pair,
	unsigned long start_blk)
{
	if (OUTDATE(pair->dram))
		pair->dram &= ~OUTDATE_BIT;
	if (UNINIT(pair->dram))
		pair->dram &= ~UNINIT_BIT;

	pair->dram |= DIRTY_BIT;
	if (start_blk < si->low_dirty)
		si->low_dirty = start_blk;
	if (start_blk > si->high_dirty)
		si->high_dirty = start_blk;

}

ssize_t pmfs_page_cache_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode_info_header *sih = si->header;
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode *pi;
	struct pmfs_file_write_entry entry_data;
	struct mem_addr *pair = NULL;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long page_addr = 0;
	size_t count, offset, copied, ret, tail;
	ssize_t	written = 0;
	loff_t pos;
	void* kmem;
	size_t bytes;
	long status = 0;
	timing_t dram_write_time, memcpy_time, find_cache_time;
	unsigned long step = 0;

	PMFS_START_TIMING(page_cache_write_t, dram_write_time);

	sb_start_write(inode->i_sb);
	mutex_lock(&inode->i_mutex);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;
	count = len;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,9)
	ret = generic_write_checks(filp, &pos, &count, S_ISBLK(inode->i_mode));
	if (ret || count == 0)
		goto out;
#endif
	pi = pmfs_get_inode(sb, inode);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	/* offset in the actual block size block */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,1,0)
	ret = file_remove_suid(filp);
#else
	ret = file_remove_privs(filp);
#endif
	if (ret) {
		goto out;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;

	pmfs_dbg_verbose("%s: ino %lu, block %llu, offset %lu, count %lu\n",
		__func__, inode->i_ino, pos >> sb->s_blocksize_bits, offset,
		count);

	/* Allocate dram pages for the required extent */
	start_blk = pos >> sb->s_blocksize_bits;
	entry_data.pgoff = start_blk;
	entry_data.num_pages = num_blocks;
	pmfs_assign_blocks(sb, pi, sih, &entry_data, NULL, 0,
					false, false, true);

	while (num_blocks > 0) {
		offset = pos & (pmfs_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;
		page_addr = 0;

		/* don't zero-out the allocated blocks */
		PMFS_START_TIMING(find_cache_t, find_cache_time);
		pair = pmfs_get_mem_pair(sb, pi, si, start_blk);
		PMFS_END_TIMING(find_cache_t, find_cache_time);

		if (pair == NULL) {
			pmfs_err(sb, "%s dram page not found!\n", __func__);
			ret = -EINVAL;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;

		page_addr = pmfs_get_dram_addr(pair);
		kmem = (void *)DRAM_ADDR(page_addr);
		pmfs_dbg_verbose("Write: 0x%lx\n", page_addr);

		tail = (offset + bytes) & (PAGE_SIZE - 1);

		pmfs_preprocess_dram_block(sb, si, pair, kmem,
						start_blk, offset, tail);

		/* Now copy from user buf */
		PMFS_START_TIMING(memcpy_w_dram_t, memcpy_time);
		copied = bytes - __copy_from_user(kmem + offset, buf, bytes);
		PMFS_END_TIMING(memcpy_w_dram_t, memcpy_time);

		if (pair->page)
			kunmap_atomic(kmem);

		pmfs_postprocess_dram_block(sb, si, pair, start_blk);

		pmfs_dbg_verbose("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= 1;
		}
		if (unlikely(copied != bytes)) {
			pmfs_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;
	}

	inode->i_blocks = le64_to_cpu(pi->i_blocks);
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

	/*
	 * We have pre-allocated page cache for the whole write range;
	 * if write fails, we still needs to update sih->i_size,
	 * otherwise we may have memory leak.
	 */
	if (status < 0 && len + *ppos > sih->i_size)
		sih->i_size = len + *ppos;

	*ppos = pos;
	ret = written;
	write_breaks += step;
//	pmfs_dbg("blocks: %lu, %llu\n", inode->i_blocks, pi->i_blocks);

out:
	mutex_unlock(&inode->i_mutex);
	sb_end_write(inode->i_sb);
	PMFS_END_TIMING(page_cache_write_t, dram_write_time);
	page_cache_write_bytes += written;
	return ret;
}

static ssize_t pmfs_flush_mmap_to_nvmm(struct super_block *sb,
	struct inode *inode, struct pmfs_inode *pi, loff_t pos,
	size_t count, void *kmem)
{
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct mem_addr *pair;
	unsigned long start_blk;
	unsigned long dram_addr;
	u64 nvmm_block;
	void *nvmm_addr;
	loff_t offset;
	size_t bytes, copied;
	ssize_t written = 0;
	int status = 0;
	ssize_t ret;

	while (count) {
		start_blk = pos >> sb->s_blocksize_bits;
		offset = pos & (sb->s_blocksize - 1);
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;

		pair = pmfs_get_mem_pair(sb, pi, si, start_blk);
		if (pair == NULL || (pair->dram == 0 && pair->page == NULL &&
				pair->nvmm_mmap == 0)) {
			pmfs_err(sb, "%s mmap page not found!\n", __func__);
			ret = -EINVAL;
			goto out;
		}

		if (pmfs_has_page_cache(sb)) {
			dram_addr = pmfs_get_dram_addr(pair);
			copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
				(void *)DRAM_ADDR(dram_addr) + offset, bytes);

			if (pair->page)
				kunmap_atomic((void *)dram_addr);

			pair->dram &= ~DIRTY_BIT;
		} else {
			nvmm_block = pair->nvmm_mmap << PAGE_SHIFT;
			nvmm_addr = pmfs_get_block(sb, nvmm_block);
			copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
				nvmm_addr + offset, bytes);
		}

		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			kmem += offset + copied;
		}
		if (unlikely(copied != bytes)) {
			pmfs_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}
	}
	ret = written;
out:
	return ret;
}

ssize_t pmfs_copy_to_nvmm(struct super_block *sb, struct inode *inode,
	struct pmfs_inode *pi, loff_t pos, size_t count, u64 *begin,
	u64 *end)
{
	struct pmfs_file_write_entry entry_data;
	unsigned long start_blk, num_blocks;
	unsigned long blocknr = 0;
	unsigned long total_blocks;
	unsigned int data_bits;
	int allocated;
	u64 curr_entry;
	ssize_t written = 0;
	int ret;
	void *kmem;
	size_t bytes, copied;
	loff_t offset;
	int status = 0;
	u64 temp_tail, begin_tail = 0;
	u32 time;
	timing_t memcpy_time, copy_to_nvmm_time;

	PMFS_START_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	sb_start_write(inode->i_sb);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	time = CURRENT_TIME_SEC.tv_sec;

	pmfs_dbgv("%s: ino %lu, block %llu, offset %lu, count %lu\n",
		__func__, inode->i_ino, pos >> sb->s_blocksize_bits,
		(unsigned long)offset, count);

	temp_tail = *end;
	while (num_blocks > 0) {
		offset = pos & (pmfs_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;
		allocated = pmfs_new_data_blocks(sb, pi, &blocknr, num_blocks,
					start_blk, pi->i_blk_type, 0, 0);
		if (allocated <= 0) {
			pmfs_err(sb, "%s alloc blocks failed!, %d\n", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = pmfs_get_block(inode->i_sb,
			pmfs_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)))
			pmfs_handle_head_tail_blocks(sb, pi, inode, pos,
							bytes, kmem);

		PMFS_START_TIMING(memcpy_w_wb_t, memcpy_time);
		copied = pmfs_flush_mmap_to_nvmm(sb, inode, pi, pos, bytes,
							kmem);
		PMFS_END_TIMING(memcpy_w_wb_t, memcpy_time);

		entry_data.pgoff = cpu_to_le32(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(pmfs_get_block_off(sb, blocknr,
							pi->i_blk_type));
		/* FIXME: should we use the page cache write time? */
		entry_data.mtime = cpu_to_le32(time);
		/* Set entry type after set block */
		pmfs_set_entry_type((void *)&entry_data, FILE_WRITE);

		entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = pmfs_append_file_write_entry(sb, pi, inode,
						&entry_data, temp_tail);
		if (curr_entry == 0) {
			pmfs_err(sb, "ERROR: append inode entry failed\n");
			ret = -EINVAL;
			goto out;
		}

		pmfs_dbgv("Write: %p, %ld\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			pmfs_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct pmfs_file_write_entry);
	}

	pmfs_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	le64_add_cpu(&pi->i_blocks,
			(total_blocks << (data_bits - sb->s_blocksize_bits)));
	pmfs_memlock_inode(sb, pi);
	inode->i_blocks = le64_to_cpu(pi->i_blocks);

	*begin = begin_tail;
	*end = temp_tail;

	ret = written;
out:
	sb_end_write(inode->i_sb);
	PMFS_END_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	fsync_bytes += written;
	return ret;
}

ssize_t pmfs_dax_file_write(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	if (!pmfs_has_page_cache(filp->f_mapping->host->i_sb)) {
		return pmfs_cow_file_write(filp, buf, len, ppos, true);
	} else {
		if (filp->f_flags & O_DIRECT)
			return pmfs_cow_file_write(filp, buf, len, ppos, true);
		else
			return pmfs_page_cache_file_write(filp, buf, len,
								ppos);
	}
}

static int pmfs_get_dram_pfn(struct super_block *sb,
	struct pmfs_inode_info *si, struct mem_addr *pair, pgoff_t pgoff,
	vm_flags_t vm_flags, void **kmem, unsigned long *pfn)
{
	unsigned long addr = 0;
	u64 bp;
	void *nvmm;
	int err;

	addr = pmfs_get_dram_addr(pair);
	if (addr == 0 || (pair->dram & OUTDATE_BIT)) {
		if (addr == 0) {
			err = pmfs_new_cache_block(sb, pair, 0, 0);
			if (err)
				return err;
			addr = pmfs_get_dram_addr(pair);
		}
		/* Copy from NVMM to dram */
		bp = __pmfs_find_nvmm_block(sb, si, pair, pgoff);
		nvmm = pmfs_get_block(sb, bp);
		memcpy((void *)DRAM_ADDR(addr), nvmm, PAGE_SIZE);
		pair->dram &= ~OUTDATE_BIT;
		pair->dram &= ~UNINIT_BIT;
	}

	if (vm_flags & VM_WRITE)
		pair->dram |= MMAP_WRITE_BIT;

	*kmem = (void *)DRAM_ADDR(addr);
	if (pair->page) {
		kunmap_atomic((void *)addr);
		*pfn = page_to_pfn(pair->page);
	} else {
		*pfn = vmalloc_to_pfn(*kmem);
	}

	return 0;
}

static int pmfs_get_nvmm_pfn(struct super_block *sb, struct pmfs_inode *pi,
	struct pmfs_inode_info *si, struct mem_addr *pair, pgoff_t pgoff,
	vm_flags_t vm_flags, void **kmem, unsigned long *pfn)
{
	u64 bp, mmap_block;
	unsigned long blocknr = 0;
	void *mmap_addr;
	void *nvmm;
	int ret;

	if (pair->nvmm_mmap) {
		mmap_block = pair->nvmm_mmap << PAGE_SHIFT;
		mmap_addr = pmfs_get_block(sb, mmap_block);
	} else {
		ret = pmfs_new_data_blocks(sb, pi, &blocknr, 1,
					pgoff, pi->i_blk_type, 0, 1);

		if (ret <= 0) {
			pmfs_err(sb, "%s alloc blocks failed!, %d\n",
					__func__, ret);
			return ret;
		}

		pair->nvmm_mmap = blocknr;
		mmap_block = blocknr << PAGE_SHIFT;
		mmap_addr = pmfs_get_block(sb, mmap_block);

		/* Copy from NVMM to dram */
		bp = __pmfs_find_nvmm_block(sb, si, pair, pgoff);
		nvmm = pmfs_get_block(sb, bp);
		memcpy(mmap_addr, nvmm,	PAGE_SIZE);
	}

	if (vm_flags & VM_WRITE)
		pair->nvmm_mmap_write = 1;

	*kmem = mmap_addr;
	*pfn = pmfs_get_pfn(sb, mmap_block);

	return 0;
}

static int pmfs_get_mmap_addr(struct inode *inode, struct vm_area_struct *vma,
	pgoff_t pgoff, int create, void **kmem, unsigned long *pfn)
{
	struct super_block *sb = inode->i_sb;
	struct pmfs_inode_info *si = PMFS_I(inode);
	struct pmfs_inode *pi;
	struct mem_addr *pair = NULL;
	vm_flags_t vm_flags = vma->vm_flags;
	int ret;

	pi = pmfs_get_inode(sb, inode);

	pair = pmfs_get_mem_pair(sb, pi, si, pgoff);
	if (pair == NULL) {
		/* This should not happen. NVMM must exist! */
		pmfs_dbg("%s: pair does not exist\n", __func__);
		return -EINVAL;
	}

	/*
	 * If pagecache is enabled, use dram mmap,
	 * otherwise use nvmm mmap.
	 */
	if (pmfs_has_page_cache(sb)) {
		ret = pmfs_get_dram_pfn(sb, si, pair, pgoff, vm_flags,
						kmem, pfn);
	} else {
		ret = pmfs_get_nvmm_pfn(sb, pi, si, pair, pgoff, vm_flags,
						kmem, pfn);
	}

	if (vm_flags & VM_WRITE) {
		if (pgoff < si->low_mmap)
			si->low_mmap = pgoff;
		if (pgoff > si->high_mmap)
			si->high_mmap = pgoff;
	}

	return ret;
}

/* OOM err return with dax file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __pmfs_dax_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *dax_mem;
	unsigned long dax_pfn;
	int err;

	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address, size);
		return VM_FAULT_SIGBUS;
	}

	err = pmfs_get_mmap_addr(inode, vma, vmf->pgoff, 1,
						&dax_mem, &dax_pfn);
	if (unlikely(err)) {
		pmfs_dbg("[%s:%d] get_mmap_addr failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		dump_stack();
		return VM_FAULT_SIGBUS;
	}

	pmfs_dbgv("%s flags: vma 0x%lx, vmf 0x%x\n",
			__func__, vma->vm_flags, vmf->flags);

	pmfs_dbg_mmapv("[%s:%d] vm_start(0x%lx), vm_end(0x%lx), pgoff(0x%lx), "
			"BlockSz(0x%lx), VA(0x%lx)->PA(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end, vmf->pgoff,
			PAGE_SIZE, (unsigned long)vmf->virtual_address,
			(unsigned long)dax_pfn << PAGE_SHIFT);

	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, dax_pfn);

	if (err == -ENOMEM)
		return VM_FAULT_SIGBUS;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);
	return VM_FAULT_NOPAGE;
}

static int pmfs_dax_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	PMFS_START_TIMING(mmap_fault_t, fault_time);
	rcu_read_lock();
	ret = __pmfs_dax_file_fault(vma, vmf);
	rcu_read_unlock();
	PMFS_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static unsigned long pmfs_data_block_size(struct vm_area_struct *vma,
				    unsigned long addr, unsigned long pgoff)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file->f_mapping->host;
	struct pmfs_inode *pi;
	unsigned long map_virt;

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;

	pi = pmfs_get_inode(inode->i_sb, inode);

	map_virt = addr & PUD_MASK;

	if (!cpu_has_gbpages || pi->i_blk_type != PMFS_BLOCK_TYPE_1G ||
	    (vma->vm_start & ~PUD_MASK) ||
	    map_virt < vma->vm_start ||
	    (map_virt + PUD_SIZE) > vma->vm_end)
		goto use_2M_mappings;

	pmfs_dbg_mmapv("[%s:%d] Using 1G Mappings : "
			"vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
			"VA(0x%lx), MAP_VA(%lx)\n", __func__, __LINE__,
			vma->vm_start, vma->vm_end, pgoff, addr, map_virt);
	return PUD_SIZE;

use_2M_mappings:
	map_virt = addr & PMD_MASK;

	if (!cpu_has_pse || pi->i_blk_type != PMFS_BLOCK_TYPE_2M ||
	    (vma->vm_start & ~PMD_MASK) ||
	    map_virt < vma->vm_start ||
	    (map_virt + PMD_SIZE) > vma->vm_end)
		goto use_4K_mappings;

	pmfs_dbg_mmapv("[%s:%d] Using 2M Mappings : "
			"vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
			"VA(0x%lx), MAP_VA(%lx)\n", __func__, __LINE__,
			vma->vm_start, vma->vm_end, pgoff, addr, map_virt);

	return PMD_SIZE;

use_4K_mappings:
	pmfs_dbg_mmapvv("[%s:%d] 4K Mappings : "
			 "vma_start(0x%lx), vma_end(0x%lx), file_pgoff(0x%lx), "
			 "VA(0x%lx)\n", __func__, __LINE__,
			 vma->vm_start, vma->vm_end, pgoff, addr);

	return PAGE_SIZE;
}

static inline pte_t *pmfs_dax_hugetlb_pte_offset(struct mm_struct *mm,
						  unsigned long	addr,
						  unsigned long *sz)
{
	return pte_offset_pagesz(mm, addr, sz);
}

static inline pte_t *pmfs_pte_alloc(struct mm_struct *mm,
				     unsigned long addr, unsigned long sz)
{
	return pte_alloc_pagesz(mm, addr, sz);
}

static pte_t pmfs_make_huge_pte(struct vm_area_struct *vma,
				 unsigned long pfn, unsigned long sz,
				 int writable)
{
	pte_t entry;

	if (writable)
		entry = pte_mkwrite(pte_mkdirty(pfn_pte(pfn, vma->vm_page_prot)));
	else
		entry = pte_wrprotect(pfn_pte(pfn, vma->vm_page_prot));

	entry = pte_mkspecial(pte_mkyoung(entry));

	if (sz != PAGE_SIZE) {
		BUG_ON(sz != PMD_SIZE && sz != PUD_SIZE);
		entry = pte_mkhuge(entry);
	}

	return entry;
}

static int __pmfs_dax_file_hpage_fault(struct vm_area_struct *vma,
					struct vm_fault *vmf)
{
	int ret;
	pte_t *ptep, new_pte;
	unsigned long size, block_sz;
	struct mm_struct *mm = vma->vm_mm;
	struct inode *inode = vma->vm_file->f_mapping->host;
	unsigned long address = (unsigned long)vmf->virtual_address;

	static DEFINE_MUTEX(pmfs_instantiation_mutex);

	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	if (vmf->pgoff >= size) {
		pmfs_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		return VM_FAULT_SIGBUS;
	}

	block_sz = pmfs_data_block_size(vma, address, vmf->pgoff);
	address &= ~(block_sz - 1);
	BUG_ON(block_sz == PAGE_SIZE);
	pmfs_dbg_mmapvv("[%s:%d] BlockSz : %lx",
			 __func__, __LINE__, block_sz);

	ptep = pmfs_pte_alloc(mm, address, block_sz);
	if (!ptep) {
		pmfs_dbg("[%s:%d] pmfs_pte_alloc failed(OOM). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		return VM_FAULT_SIGBUS;
	}

	/* Serialize hugepage allocation and instantiation, so that we don't
	 * get spurious allocation failures if two CPUs race to instantiate
	 * the same page in the page cache.
	 */
	mutex_lock(&pmfs_instantiation_mutex);
	if (pte_none(*ptep)) {
		void *dax_mem;
		unsigned long dax_pfn;
		if (pmfs_get_mmap_addr(inode, vma, vmf->pgoff, 1,
						&dax_mem, &dax_pfn) != 0) {
			pmfs_dbg("[%s:%d] get_mmap_addr failed. vm_start(0x"
				"%lx), vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
				__func__, __LINE__, vma->vm_start,
				vma->vm_end, vmf->pgoff,
				(unsigned long)vmf->virtual_address);
			ret = VM_FAULT_SIGBUS;
			goto out_mutex;
		}

		/* VA has already been aligned. Align dax_pfn to block_sz. */
		dax_pfn <<= PAGE_SHIFT;
		dax_pfn &= ~(block_sz - 1);
		dax_pfn >>= PAGE_SHIFT;
		new_pte = pmfs_make_huge_pte(vma, dax_pfn, block_sz,
					      ((vma->vm_flags & VM_WRITE) &&
					       (vma->vm_flags & VM_SHARED)));
		/* FIXME: Is lock necessary ? */
		spin_lock(&mm->page_table_lock);
		set_pte_at(mm, address, ptep, new_pte);
		spin_unlock(&mm->page_table_lock);

		if (ptep_set_access_flags(vma, address, ptep, new_pte,
					  vmf->flags & FAULT_FLAG_WRITE))
			update_mmu_cache(vma, address, ptep);
	}
	ret = VM_FAULT_NOPAGE;

out_mutex:
	mutex_unlock(&pmfs_instantiation_mutex);
	return ret;
}

static int pmfs_dax_file_hpage_fault(struct vm_area_struct *vma,
							struct vm_fault *vmf)
{
	int ret = 0;

	rcu_read_lock();
	ret = __pmfs_dax_file_hpage_fault(vma, vmf);
	rcu_read_unlock();
	return ret;
}

static const struct vm_operations_struct pmfs_dax_vm_ops = {
	.fault	= pmfs_dax_file_fault,
};

static const struct vm_operations_struct pmfs_dax_hpage_vm_ops = {
	.fault	= pmfs_dax_file_hpage_fault,
};

static inline int pmfs_has_huge_mmap(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = (struct pmfs_sb_info *)sb->s_fs_info;

	return sbi->s_mount_opt & PMFS_MOUNT_HUGEMMAP;
}

int pmfs_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long block_sz;

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP;

	block_sz = pmfs_data_block_size(vma, vma->vm_start, 0);
	if (pmfs_has_huge_mmap(file->f_mapping->host->i_sb) &&
	    (vma->vm_flags & VM_SHARED) &&
	    (block_sz == PUD_SIZE || block_sz == PMD_SIZE)) {
		/* vma->vm_flags |= (VM_XIP_HUGETLB | VM_SHARED | VM_DONTCOPY); */
		vma->vm_flags |= VM_XIP_HUGETLB;
		vma->vm_ops = &pmfs_dax_hpage_vm_ops;
		pmfs_dbg_mmaphuge("[%s:%d] MMAP HUGEPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end, vma->vm_flags,
			pgprot_val(vma->vm_page_prot));
	} else {
		vma->vm_ops = &pmfs_dax_vm_ops;
		pmfs_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));
	}

	return 0;
}
