/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "nova.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

struct nova_dir_logentry *nova_find_dir_logentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	struct nova_dir_logentry *direntry;
	unsigned int hash;

	hash = BKDRHash(name, name_len);
	direntry = radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

static int nova_insert_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dir_logentry *direntry)
{
	unsigned int hash;
	int ret;

	hash = BKDRHash(name, namelen);
	nova_dbgv("%s: insert %s @ %p\n", __func__, name, direntry);

	/* FIXME: hash collision ignored here */
	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret)
		nova_dbg("%s ERROR %d: %s\n", __func__, ret, name);

	return ret;
}

void nova_remove_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen)
{
	unsigned int hash;

	hash = BKDRHash(name, namelen);
	radix_tree_delete(&sih->tree, hash);
}

void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_dir_logentry *direntry;
	unsigned long pos = 0;
	struct nova_dir_logentry *entries[FREE_BATCH];
	timing_t delete_time;
	int nr_entries;
	int i;
	void *ret;

	NOVA_START_TIMING(delete_dir_tree_t, delete_time);

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			direntry = entries[i];
			BUG_ON(!direntry);
			pos = BKDRHash(direntry->name, direntry->name_len);
			ret = radix_tree_delete(&sih->tree, pos);
			BUG_ON(!ret || ret != direntry);
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	NOVA_END_TIMING(delete_dir_tree_t, delete_time);
	return;
}

/* ========================= Entry operations ============================= */

/*
 * Append a nova_dir_logentry to the current nova_inode_log_page.
 * Note unlike append_file_write_entry(), this method returns the tail pointer
 * after append.
 */
static u64 nova_append_dir_inode_entry(struct super_block *sb,
	struct nova_inode *pidir, struct inode *dir, u64 *pi_addr,
	u64 ino, struct dentry *dentry, unsigned short de_len, u64 tail,
	int link_change, int new_inode,	u64 *curr_tail)
{
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = si->header;
	struct nova_dir_logentry *entry;
	u64 curr_p, inode_start;
	size_t size = de_len;
	unsigned short links_count;
	timing_t append_time;

	NOVA_START_TIMING(append_entry_t, append_time);

	curr_p = nova_get_append_head(sb, pidir, sih, tail,
						size, new_inode, 0);
	if (curr_p == 0)
		BUG();

	entry = (struct nova_dir_logentry *)nova_get_block(sb, curr_p);
	entry->entry_type = DIR_LOG;
	entry->ino = cpu_to_le64(ino);
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
				dentry->d_name.len);
	entry->file_type = 0;
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	entry->size = cpu_to_le64(dir->i_size);
	entry->new_inode = new_inode;

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	/* Update actual de_len */
	entry->de_len = cpu_to_le16(de_len);
	nova_dbg_verbose("dir entry @ 0x%llx: ino %llu, entry len %u, "
			"name len %u, file type %u\n",
			curr_p, entry->ino, entry->de_len,
			entry->name_len, entry->file_type);

	nova_flush_buffer(entry, de_len, 0);

	*curr_tail = curr_p + de_len;

	if (new_inode) {
		/* Allocate space for the new inode */
		if (is_last_entry(curr_p, de_len, new_inode))
			inode_start = next_log_page(sb, curr_p);
		else
			inode_start = (*curr_tail & (CACHELINE_SIZE - 1)) == 0
				? *curr_tail : CACHE_ALIGN(*curr_tail) +
						CACHELINE_SIZE;

		if (pi_addr)
			*pi_addr = inode_start;

		*curr_tail = inode_start + NOVA_INODE_SIZE;
	}

	dir->i_blocks = pidir->i_blocks;
	NOVA_END_TIMING(append_entry_t, append_time);
	return curr_p;
}

/* Append . and .. entries */
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino)
{
	int allocated;
	u64 new_block;
	u64 curr_p;
	struct nova_dir_logentry *de_entry;

	if (pi->log_head) {
		nova_dbg("%s: log head exists @ 0x%llx!\n",
				__func__, pi->log_head);
		return - EINVAL;
	}

	allocated = nova_allocate_inode_log_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return - ENOMEM;
	}
	pi->log_tail = pi->log_head = new_block;
	pi->i_blocks = 1;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	de_entry = (struct nova_dir_logentry *)nova_get_block(sb, new_block);
	de_entry->entry_type = DIR_LOG;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(NOVA_DIR_LOG_REC_LEN(1));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, ".", 1);
	nova_flush_buffer(de_entry, NOVA_DIR_LOG_REC_LEN(1), 0);

	curr_p = new_block + NOVA_DIR_LOG_REC_LEN(1);

	de_entry = (struct nova_dir_logentry *)((char *)de_entry +
					le16_to_cpu(de_entry->de_len));
	de_entry->entry_type = DIR_LOG;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(NOVA_DIR_LOG_REC_LEN(2));
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 2;
	strncpy(de_entry->name, "..", 2);
	nova_flush_buffer(de_entry, NOVA_DIR_LOG_REC_LEN(2), 0);

	curr_p += NOVA_DIR_LOG_REC_LEN(2);
	nova_update_tail(pi, curr_p);

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_add_entry(struct dentry *dentry, u64 *pi_addr, u64 ino, int inc_link,
	int new_inode, u64 tail, u64 *new_tail)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = si->header;
	struct nova_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct nova_dir_logentry *direntry;
	unsigned short loglen;
	int ret;
	u64 curr_entry, curr_tail;
	timing_t add_entry_time;

	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);
	NOVA_START_TIMING(add_entry_t, add_entry_time);
	if (namelen == 0)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	loglen = NOVA_DIR_LOG_REC_LEN(namelen);
	curr_entry = nova_append_dir_inode_entry(sb, pidir, dir, pi_addr, ino,
				dentry,	loglen, tail, inc_link, new_inode,
				&curr_tail);

	direntry = (struct nova_dir_logentry *)nova_get_block(sb, curr_entry);
	ret = nova_insert_dir_radix_tree(sb, sih, name, namelen, direntry);
	*new_tail = curr_tail;
	NOVA_END_TIMING(add_entry_t, add_entry_time);
	return ret;
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_remove_entry(struct dentry *dentry, int dec_link, u64 tail,
	u64 *new_tail)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = si->header;
	struct nova_inode *pidir;
	struct qstr *entry = &dentry->d_name;
	unsigned short loglen;
	u64 curr_tail, curr_entry;
	timing_t remove_entry_time;

	NOVA_START_TIMING(remove_entry_t, remove_entry_time);

	if (!dentry->d_name.len)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	loglen = NOVA_DIR_LOG_REC_LEN(entry->len);
	curr_entry = nova_append_dir_inode_entry(sb, pidir, dir, NULL, 0,
				dentry, loglen, tail, dec_link, 0, &curr_tail);
	nova_remove_dir_radix_tree(sb, sih, entry->name, entry->len);
	*new_tail = curr_tail;

	NOVA_END_TIMING(remove_entry_t, remove_entry_time);
	return 0;
}

inline int nova_replay_add_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dir_logentry *entry)
{
	if (!entry->name_len)
		return -EINVAL;

	nova_dbg_verbose("%s: add %s\n", __func__, entry->name);
	return nova_insert_dir_radix_tree(sb, sih,
			entry->name, entry->name_len, entry);
}

inline int nova_replay_remove_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_dir_logentry *entry)
{
	nova_dbg_verbose("%s: remove %s\n", __func__, entry->name);
	nova_remove_dir_radix_tree(sb, sih, entry->name,
					entry->name_len);
	return 0;
}

static inline void nova_rebuild_dir_time_and_size(struct super_block *sb,
	struct nova_inode *pi, struct nova_dir_logentry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = entry->mtime;
	pi->i_mtime = entry->mtime;
	pi->i_size = entry->size;
	pi->i_links_count = entry->links_count;
}

int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih, struct scan_bitmap *bm)
{
	struct nova_dir_logentry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *link_change_entry = NULL;
	struct nova_inode_log_page *curr_page;
	u64 ino = pi->nova_ino;
	unsigned short de_len;
	void *addr;
	u64 curr_p;
	u64 next;
	u8 type;
	int ret;

	nova_dbg_verbose("Rebuild dir %llu tree\n", ino);

	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		nova_err(sb, "Dir %llu log is NULL!\n", ino);
		BUG();
	}

	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, pi->log_tail);
	if (bm) {
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
	}
	sih->log_pages = 1;
	while (curr_p != pi->log_tail) {
		if (is_last_dir_entry(sb, curr_p)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
			if (bm) {
				BUG_ON(curr_p & (PAGE_SIZE - 1));
				set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
			}
		}

		if (curr_p == 0) {
			nova_err(sb, "Dir %llu log is NULL!\n", ino);
			BUG();
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				attr_entry =
					(struct nova_setattr_logentry *)addr;
				nova_apply_setattr_entry(pi, attr_entry);
				curr_p += sizeof(struct nova_setattr_logentry);
				continue;
			case LINK_CHANGE:
				link_change_entry =
					(struct nova_link_change_entry *)addr;
				nova_apply_link_change_entry(pi,
							link_change_entry);
				curr_p += sizeof(struct nova_link_change_entry);
				continue;
			case DIR_LOG:
				break;
			default:
				nova_dbg("%s: unknown type %d, 0x%llx\n",
							__func__, type, curr_p);
				NOVA_ASSERT(0);
		}

		entry = (struct nova_dir_logentry *)nova_get_block(sb, curr_p);
		nova_dbg_verbose("curr_p: 0x%llx, type %d, ino %llu, "
			"name %*.s, namelen %u, rec len %u\n", curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name_len, entry->name,
			entry->name_len, le16_to_cpu(entry->de_len));

		if (entry->ino > 0) {
			/* A valid entry to add */
			ret = nova_replay_add_entry(sb, sih, entry);
		} else {
			/* Delete the entry */
			ret = nova_replay_remove_entry(sb, sih, entry);
		}

		if (ret) {
			nova_err(sb, "%s ERROR %d\n", __func__, ret);
			break;
		}

		nova_rebuild_dir_time_and_size(sb, pi, entry);

		de_len = le16_to_cpu(entry->de_len);
		curr_p += de_len;

		/*
		 * If following by a new inode, find the inode
		 * and its end first
		 */
		if (entry->new_inode) {
			if (is_last_entry(curr_p - de_len, de_len, 1)) {
				sih->log_pages++;
				curr_p = next_log_page(sb, curr_p);
				if (bm) {
					BUG_ON(curr_p & (PAGE_SIZE - 1));
					set_bm(curr_p >> PAGE_SHIFT,
							bm, BM_4K);
				}
			} else {
				curr_p = (curr_p & (CACHELINE_SIZE - 1)) == 0 ?
					curr_p : CACHE_ALIGN(curr_p) +
							CACHELINE_SIZE;
			}
			/* If power failure, recover the inode in DFS way */
			if (bm)
				nova_recover_inode(sb, curr_p,
						bm, smp_processor_id(), 0);

			curr_p += NOVA_INODE_SIZE;
		}
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le64_to_cpu(pi->i_mode);
	nova_flush_buffer(pi, sizeof(struct nova_inode), 0);

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr_p);
	while ((next = curr_page->page_tail.next_page) != 0) {
		sih->log_pages++;
		curr_p = next;
		if (bm) {
			BUG_ON(curr_p & (PAGE_SIZE - 1));
			set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
		}
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr_p);
	}

	if (bm)
		pi->i_blocks += sih->log_pages;

//	nova_print_dir_tree(sb, sih, ino);
	return 0;
}

static int nova_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = si->header;
	struct nova_inode_info_header *child_sih;
	struct nova_dir_logentry *entry;
	struct nova_dir_logentry *entries[FREE_BATCH];
	int nr_entries;
	long pos = 0;
	ino_t ino;
	int i;
	timing_t readdir_time;

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %llu, size %llu, pos %llu\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (!sih) {
		nova_dbg("%s: inode %lu sih does not exist!\n",
				__func__, inode->i_ino);
		ctx->pos = READDIR_END;
		return 0;
	}

	pos = ctx->pos;
	if (pos == READDIR_END)
		goto out;

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			entry = entries[i];
			pos = BKDRHash(entry->name, entry->name_len);
			ino = __le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;

			child_sih = nova_find_info_header(sb, ino);
			nova_dbgv("ctx: ino %llu, name %*.s, "
				"name_len %u, de_len %u\n",
				(u64)ino, entry->name_len, entry->name,
				entry->name_len, entry->de_len);
			if (!child_sih) {
				nova_dbg("%s: child inode %lu sih "
					"does not exist!\n",
					__func__, ino);
				ctx->pos = READDIR_END;
				return 0;
			}
			if (!dir_emit(ctx, entry->name, entry->name_len,
				ino, IF2DT(le16_to_cpu(child_sih->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				ctx->pos = pos;
				return 0;
			}
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	/*
	 * We have reach the end. To let readdir be aware of that, we assign
	 * a bogus end offset to ctx.
	 */
	ctx->pos = READDIR_END;
out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	return 0;
}

const struct file_operations nova_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= nova_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = nova_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nova_compat_ioctl,
#endif
};
