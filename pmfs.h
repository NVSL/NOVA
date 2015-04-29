/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the PMFS filesystem.
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
#ifndef __PMFS_H
#define __PMFS_H

#include <linux/crc16.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/rbtree.h>

#include "pmfs_def.h"
#include "journal.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_1G 30

#define PMFS_ASSERT(x)                                                 \
	if (!(x)) {                                                     \
		printk(KERN_WARNING "assertion failed %s:%d: %s\n",     \
	               __FILE__, __LINE__, #x);                         \
	}

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define pmfs_dbg(s, args...)         pr_debug(s, ## args) */
#define pmfs_dbg(s, args ...)           pr_info(s, ## args)
#define pmfs_dbg1(s, args ...)
#define pmfs_err(sb, s, args ...)       pmfs_error_mng(sb, s, ## args)
#define pmfs_warn(s, args ...)          pr_warning(s, ## args)
#define pmfs_info(s, args ...)          pr_info(s, ## args)

extern unsigned int pmfs_dbgmask;
#define PMFS_DBGMASK_MMAPHUGE          (0x00000001)
#define PMFS_DBGMASK_MMAP4K            (0x00000002)
#define PMFS_DBGMASK_MMAPVERBOSE       (0x00000004)
#define PMFS_DBGMASK_MMAPVVERBOSE      (0x00000008)
#define PMFS_DBGMASK_VERBOSE           (0x00000010)
#define PMFS_DBGMASK_TRANSACTION       (0x00000020)

#define pmfs_dbg_mmaphuge(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_MMAPHUGE) ? pmfs_dbg(s, args) : 0)
#define pmfs_dbg_mmap4k(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_MMAP4K) ? pmfs_dbg(s, args) : 0)
#define pmfs_dbg_mmapv(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_MMAPVERBOSE) ? pmfs_dbg(s, args) : 0)
#define pmfs_dbg_mmapvv(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_MMAPVVERBOSE) ? pmfs_dbg(s, args) : 0)

#define pmfs_dbg_verbose(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_VERBOSE) ? pmfs_dbg(s, ##args) : 0)
//#define pmfs_dbg_verbose(s, args ...)	pmfs_dbg(s, ##args)
#define pmfs_dbg_trans(s, args ...)		 \
	((pmfs_dbgmask & PMFS_DBGMASK_TRANSACTION) ? pmfs_dbg(s, ##args) : 0)

#define pmfs_set_bit                   __test_and_set_bit_le
#define pmfs_clear_bit                 __test_and_clear_bit_le
#define pmfs_find_next_zero_bit                find_next_zero_bit_le

#define clear_opt(o, opt)       (o &= ~PMFS_MOUNT_ ## opt)
#define set_opt(o, opt)         (o |= PMFS_MOUNT_ ## opt)
#define test_opt(sb, opt)       (PMFS_SB(sb)->s_mount_opt & PMFS_MOUNT_ ## opt)

#define PMFS_LARGE_INODE_TABLE_SIZE    (0x200000)
/* PMFS size threshold for using 2M blocks for inode table */
#define PMFS_LARGE_INODE_TABLE_THREASHOLD    (0x20000000)
/*
 * pmfs inode flags
 *
 * PMFS_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define PMFS_EOFBLOCKS_FL      0x20000000
/* Flags that should be inherited by new inodes from their parent. */
#define PMFS_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
			    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
			    FS_COMPRBLK_FL | FS_NOCOMP_FL | FS_JOURNAL_DATA_FL | \
			    FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define PMFS_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define PMFS_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define PMFS_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | PMFS_EOFBLOCKS_FL)

#define INODES_PER_BLOCK(bt) (1 << (blk_type_to_shift[bt] - PMFS_INODE_BITS))

/* IOCTLs */
#define	FS_PMFS_FSYNC			0xBCD0000E
#define	PMFS_PRINT_TIMING		0xBCD00010
#define	PMFS_CLEAR_STATS		0xBCD00011
#define	PMFS_COW_WRITE			0xBCD00012
#define	PMFS_PRINT_LOG			0xBCD00013
#define	PMFS_PRINT_LOG_BLOCKNODE	0xBCD00014
#define	PMFS_PRINT_LOG_PAGE		0xBCD00015
#define	PMFS_MALLOC_TEST		0xBCD00016


#define	READDIR_END			0x1

extern unsigned int blk_type_to_shift[PMFS_BLOCK_TYPE_MAX];
extern unsigned int blk_type_to_size[PMFS_BLOCK_TYPE_MAX];

/* ======================= Timing ========================= */
enum timing_category {
	ioremap_t,
	/* Namei operations */
	create_t,
	lookup_t,
	link_t,
	unlink_t,
	symlink_t,
	mkdir_t,
	rmdir_t,
	mknod_t,
	rename_t,
	readdir_t,
	new_inode_t,
	add_entry_t,
	remove_entry_t,
	setattr_t,

	/* I/O operations */
	xip_read_t,
	cow_write_t,
	page_cache_write_t,
	copy_to_nvmm_t,

	/* Memory operations */
	memcpy_r_nvmm_t,
	memcpy_r_dram_t,
	memcpy_w_nvmm_t,
	memcpy_w_dram_t,
	memcpy_w_wb_t,
	partial_block_t,

	/* Memory management */
	new_data_blocks_t,
	new_meta_blocks_t,
	new_cache_page_t,
	free_data_t,
	free_meta_t,

	/* Logging and journaling */
	logging_t,
	append_entry_t,
	log_gc_t,
	check_invalid_t,

	/* Others */
	find_cache_t,
	assign_t,
	fsync_t,
	direct_IO_t,
	evict_inode_t,
	mmap_fault_t,
	malloc_test_t,

	/* Sentinel */
	TIMING_NUM,
};

extern const char *Timingstring[TIMING_NUM];
extern unsigned long long Timingstats[TIMING_NUM];
extern u64 Countstats[TIMING_NUM];
extern unsigned long long read_bytes;
extern unsigned long long cow_write_bytes;
extern unsigned long long page_cache_write_bytes;
extern unsigned long long fsync_bytes;
extern unsigned long long checked_pages;
extern unsigned long gc_pages;

extern int measure_timing;
extern int contiguous_allocation;

typedef struct timespec timing_t;

#define PMFS_START_TIMING(name, start) \
	{if (measure_timing) getrawmonotonic(&start);}

#define PMFS_END_TIMING(name, start) \
	{if (measure_timing) { \
		timing_t end; \
		getrawmonotonic(&end); \
		Timingstats[name] += \
			(end.tv_sec - start.tv_sec) * 1000000000 + \
			(end.tv_nsec - start.tv_nsec); \
	} \
	Countstats[name]++; \
	}

extern unsigned long alloc_steps;
extern unsigned long free_steps;
extern unsigned long write_breaks;

/* ======================= Inode log ========================= */
/* Inode entry in th log */

#define	INVALID_MASK	4095
#define	BLOCK_OFF(p)	((p) & ~INVALID_MASK)
#define	GET_INVALID(p)	((p) & INVALID_MASK)

#define	ENTRY_LOC(p)	((p) & INVALID_MASK)

struct	pmfs_inode_entry {
	u32	pgoff;
	u32	num_pages;
	/* ret of find_data_block, last 12 bits are invalid count */
	u64	block;
	u32	ctime;
	u32	mtime;
	u64	size;
};

struct	pmfs_inode_page_tail {
	u64	padding1;
	u64	padding2;
	u64	padding3;
	u64	next_page;
};

#define	ENTRIES_PER_PAGE	127

/* Fit in PAGE_SIZE */
struct	pmfs_inode_log_page {
	struct pmfs_inode_entry entries[ENTRIES_PER_PAGE];
	struct pmfs_inode_page_tail page_tail;
};

#define	LAST_ENTRY	4064
#define	PAGE_TAIL(p)	(((p) & ~INVALID_MASK) + LAST_ENTRY)

struct pmfs_dir_node {
	struct rb_node node;
	unsigned long nvmm;
};


/* Function Prototypes */
extern void pmfs_error_mng(struct super_block *sb, const char *fmt, ...);

/* file.c */
extern int pmfs_mmap(struct file *file, struct vm_area_struct *vma);

/* balloc.c */
int pmfs_setup_blocknode_map(struct super_block *sb);
extern struct pmfs_blocknode *pmfs_alloc_blocknode(struct super_block *sb);
extern void pmfs_free_blocknode(struct super_block *sb, struct pmfs_blocknode *bnode);
extern void pmfs_init_blockmap(struct super_block *sb,
		unsigned long init_used_size);
void __pmfs_free_block(struct super_block *sb, unsigned long blocknr,
		unsigned short btype, struct pmfs_blocknode **start_hint,
		int log_block);
extern void pmfs_free_data_block(struct super_block *sb, unsigned long blocknr,
	unsigned short btype);
extern void pmfs_free_meta_block(struct super_block *sb, unsigned long blocknr);
extern void __pmfs_free_data_block(struct super_block *sb,
	unsigned long blocknr,
	unsigned short btype, struct pmfs_blocknode **start_hint);
extern void __pmfs_free_log_block(struct super_block *sb,
	unsigned long blocknr,
	unsigned short btype, struct pmfs_blocknode **start_hint);
extern int pmfs_new_data_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned int num, unsigned short btype, int zero);
extern int pmfs_new_meta_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned int num, int zero);
extern unsigned long pmfs_count_free_blocks(struct super_block *sb);
unsigned long pmfs_alloc_dram_page(struct super_block *sb, int zero);
void pmfs_free_dram_page(unsigned long page_addr);

/* dir.c */
extern int pmfs_add_entry(pmfs_transaction_t *trans,
		struct dentry *dentry, struct inode *inode, int inc_link);
extern int pmfs_remove_entry(pmfs_transaction_t *trans,
		struct dentry *dentry, struct inode *inode, int dec_link);
int pmfs_rebuild_dir_inode_tree(struct super_block *sb, struct inode *inode,
			struct pmfs_inode *pi);

/* namei.c */
extern struct dentry *pmfs_get_parent(struct dentry *child);

/* inode.c */
extern unsigned int pmfs_free_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr);
extern unsigned int pmfs_free_file_inode_subtree(struct super_block *sb,
		__le64 root, u32 height, u32 btype, unsigned long last_blocknr);
extern int __pmfs_alloc_blocks(pmfs_transaction_t *trans,
		struct super_block *sb, struct pmfs_inode *pi,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern int pmfs_init_inode_table(struct super_block *sb);
extern int pmfs_alloc_blocks(pmfs_transaction_t *trans, struct inode *inode,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern int pmfs_alloc_dir_blocks(struct inode *inode,
		unsigned long file_blocknr, unsigned int num, bool zero);
extern int pmfs_assign_blocks(struct inode *inode, unsigned long file_blocknr,
		unsigned int num, u64 curr_entry, bool nvmm, bool free,
		bool alloc_dram);
extern u64 pmfs_find_data_block(struct inode *inode,
		unsigned long file_blocknr, bool nvmm);
extern u64 pmfs_find_inode(struct inode *inode,
		unsigned long file_blocknr);
extern u64 pmfs_find_dir_block(struct inode *inode,
		unsigned long file_blocknr);
int pmfs_set_blocksize_hint(struct super_block *sb, struct pmfs_inode *pi,
		loff_t new_size);
void pmfs_setsize(struct inode *inode, loff_t newsize);

extern struct inode *pmfs_iget(struct super_block *sb, unsigned long ino,
		int rebuild);
extern void pmfs_put_inode(struct inode *inode);
extern void pmfs_evict_inode(struct inode *inode);
extern struct inode *pmfs_new_inode(pmfs_transaction_t *trans,
	struct inode *dir, umode_t mode, const struct qstr *qstr);
extern void pmfs_update_isize(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_update_nlink(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_update_time(struct inode *inode, struct pmfs_inode *pi);
extern int pmfs_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void pmfs_dirty_inode(struct inode *inode, int flags);
extern int pmfs_notify_change(struct dentry *dentry, struct iattr *attr);
int pmfs_getattr(struct vfsmount *mnt, struct dentry *dentry, 
		struct kstat *stat);
extern void pmfs_set_inode_flags(struct inode *inode, struct pmfs_inode *pi);
extern void pmfs_get_inode_flags(struct inode *inode, struct pmfs_inode *pi);
extern unsigned long pmfs_find_region(struct inode *inode, loff_t *offset,
		int hole);
extern void pmfs_truncate_del(struct inode *inode);
extern void pmfs_truncate_add(struct inode *inode, u64 truncate_size);

/* ioctl.c */
extern long pmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long pmfs_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif

/* super.c */
#ifdef CONFIG_PMFS_TEST
extern struct pmfs_super_block *get_pmfs_super(void);
#endif
extern void __pmfs_free_blocknode(struct pmfs_blocknode *bnode);
extern struct super_block *pmfs_read_super(struct super_block *sb, void *data,
	int silent);
extern int pmfs_statfs(struct dentry *d, struct kstatfs *buf);
extern int pmfs_remount(struct super_block *sb, int *flags, char *data);
struct pmfs_dir_node *pmfs_alloc_dirnode(struct super_block *sb);
void pmfs_free_dirnode(struct super_block *sb, struct pmfs_dir_node *node);

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}

static inline void pmfs_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;
	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	for (i = 0; i < len; i += CACHELINE_SIZE)
		asm volatile ("clflush %0\n" : "+m" (*(char *)(buf+i)));
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence. */
	if (fence)
		asm volatile ("sfence\n" : : );
}

/* symlink.c */
extern int pmfs_block_symlink(struct inode *inode, const char *symname,
	int len);

/* Inline functions start here */

/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 pmfs_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(PMFS_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(PMFS_REG_FLMASK);
	else
		return flags & cpu_to_le32(PMFS_OTHER_FLMASK);
}

static inline int pmfs_calc_checksum(u8 *data, int n)
{
	u16 crc = 0;

	crc = crc16(~0, (__u8 *)data + sizeof(__le16), n - sizeof(__le16));
	if (*((__le16 *)data) == cpu_to_le16(crc))
		return 0;
	else
		return 1;
}

struct pmfs_blocknode_lowhigh {
       __le64 block_low;
       __le64 block_high;
};
               
struct pmfs_blocknode {
	struct list_head link;
	unsigned long block_low;
	unsigned long block_high;
};

struct pmfs_inode_info {
	__u32   i_dir_start_lookup;
	struct list_head i_truncated;
	struct inode	vfs_inode;
	struct rb_root	dir_tree;
};

/*
 * PMFS super-block data in memory
 */
struct pmfs_sb_info {
	/*
	 * base physical and virtual address of PMFS (which is also
	 * the pointer to the super block)
	 */
	phys_addr_t	phys_addr;
	void		*virt_addr;
	struct list_head block_inuse_head;
	unsigned long	block_start;
	unsigned long	block_end;
	unsigned long	num_free_blocks;
	struct mutex 	s_lock;	/* protects the SB's buffer-head */

	/*
	 * Backing store option:
	 * 1 = no load, 2 = no store,
	 * else do both
	 */
	unsigned int	pmfs_backing_option;

	/* Mount options */
	unsigned long	bpi;
	unsigned long	num_inodes;
	unsigned long	blocksize;
	unsigned long	initsize;
	unsigned long	s_mount_opt;
	kuid_t		uid;    /* Mount uid for root directory */
	kgid_t		gid;    /* Mount gid for root directory */
	umode_t		mode;   /* Mount mode for root directory */
	atomic_t	next_generation;
	/* inode tracking */
	struct mutex inode_table_mutex;
	unsigned int	s_inodes_count;  /* total inodes count (used or free) */
	unsigned int	s_free_inodes_count;    /* free inodes count */
	unsigned int	s_inodes_used_count;
	unsigned int	s_free_inode_hint;
	unsigned int	s_max_inode;

	unsigned long num_blocknode_allocated;

	/* Journaling related structures */
	uint32_t    next_transaction_id;
	uint32_t    jsize;
	void       *journal_base_addr;
	struct mutex journal_mutex;
	struct task_struct *log_cleaner_thread;
	wait_queue_head_t  log_cleaner_wait;
	bool redo_log;

	/* truncate list related structures */
	struct list_head s_truncate;
	struct mutex s_truncate_lock;
};

static inline struct pmfs_sb_info *PMFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct pmfs_inode_info *PMFS_I(struct inode *inode)
{
	return container_of(inode, struct pmfs_inode_info, vfs_inode);
}

extern struct pmfs_inode_info *root_info;
static inline struct pmfs_inode_info *PMFS_GET_INFO(struct inode *inode)
{
	if (inode->i_ino == PMFS_ROOT_INO)
		return root_info;
	else
		return container_of(inode, struct pmfs_inode_info, vfs_inode);
}

/* If this is part of a read-modify-write of the super block,
 * pmfs_memunlock_super() before calling! */
static inline struct pmfs_super_block *pmfs_get_super(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	return (struct pmfs_super_block *)sbi->virt_addr;
}

static inline pmfs_journal_t *pmfs_get_journal(struct super_block *sb)
{
	struct pmfs_super_block *ps = pmfs_get_super(sb);

	return (pmfs_journal_t *)((char *)ps +
			le64_to_cpu(ps->s_journal_offset));
}

static inline struct pmfs_inode *pmfs_get_inode_table(struct super_block *sb)
{
	struct pmfs_super_block *ps = pmfs_get_super(sb);

	return (struct pmfs_inode *)((char *)ps +
			le64_to_cpu(ps->s_inode_table_offset));
}

static inline struct pmfs_super_block *pmfs_get_redund_super(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = PMFS_SB(sb);

	return (struct pmfs_super_block *)(sbi->virt_addr + PMFS_SB_SIZE);
}

/* If this is part of a read-modify-write of the block,
 * pmfs_memunlock_block() before calling! */
static inline void *pmfs_get_block(struct super_block *sb, u64 block)
{
	struct pmfs_super_block *ps = pmfs_get_super(sb);

	return block ? ((void *)ps + block) : NULL;
}

/* uses CPU instructions to atomically write up to 8 bytes */
static inline void pmfs_memcpy_atomic (void *dst, const void *src, u8 size)
{
	switch (size) {
		case 1: {
			volatile u8 *daddr = dst;
			const u8 *saddr = src;
			*daddr = *saddr;
			break;
		}
		case 2: {
			volatile __le16 *daddr = dst;
			const u16 *saddr = src;
			*daddr = cpu_to_le16(*saddr);
			break;
		}
		case 4: {
			volatile __le32 *daddr = dst;
			const u32 *saddr = src;
			*daddr = cpu_to_le32(*saddr);
			break;
		}
		case 8: {
			volatile __le64 *daddr = dst;
			const u64 *saddr = src;
			*daddr = cpu_to_le64(*saddr);
			break;
		}
		default:
			pmfs_dbg("error: memcpy_atomic called with %d bytes\n", size);
			//BUG();
	}
}

static inline void pmfs_update_time_and_size(struct inode *inode,
	struct pmfs_inode *pi)
{
	__le32 words[2];
	__le64 new_pi_size = cpu_to_le64(i_size_read(inode));

	/* pi->i_size, pi->i_ctime, and pi->i_mtime need to be atomically updated.
 	* So use cmpxchg16b here. */
	words[0] = cpu_to_le32(inode->i_ctime.tv_sec);
	words[1] = cpu_to_le32(inode->i_mtime.tv_sec);
	/* TODO: the following function assumes cmpxchg16b instruction writes
 	* 16 bytes atomically. Confirm if it is really true. */
	cmpxchg_double_local(&pi->i_size, (u64 *)&pi->i_ctime, pi->i_size,
		*(u64 *)&pi->i_ctime, new_pi_size, *(u64 *)words);
}

/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:      movnti %%rax,(%%rdi)\n"
		"2:      movnti %%rax,1*8(%%rdi)\n"
		"3:      movnti %%rax,2*8(%%rdi)\n"
		"4:      movnti %%rax,3*8(%%rdi)\n"
		"5:      movnti %%rax,4*8(%%rdi)\n"
		"8:      movnti %%rax,5*8(%%rdi)\n"
		"7:      movnti %%rax,6*8(%%rdi)\n"
		"8:      movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:     movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:     movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:     movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2) : "D" (dest), "a" (qword), "d" (length) : "memory", "rcx");
}

static inline u64 __pmfs_find_inode(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);

	while (height > 0) {
		level_ptr = pmfs_get_block(sb, bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}
	return bp;
}

#define	DRAM_BIT	0x1UL	// DRAM
#define	KMALLOC_BIT	0x2UL	// Alloc with kmalloc
#define	GETPAGE_BIT	0x4UL	// Alloc with get_free_page
#define	DIRTY_BIT	0x8UL	// Dirty
#define	OUTDATE_BIT	0x10UL	// Outdate with NVMM page
#define	IS_DRAM_ADDR(p)	((p) & (DRAM_BIT))
#define	IS_DIRTY(p)	((p) & (DIRTY_BIT))
#define	OUTDATE(p)	((p) & (OUTDATE_BIT))
#define	DRAM_ADDR(p)	((p) & (PAGE_MASK))

#define	MAX_BLOCK	((1UL << 32) - 1)

struct mem_addr {
	unsigned long nvmm;	// inode entry
	unsigned long dram;	// DRAM virtual address
};

static inline u64 __pmfs_find_data_block(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr, bool nvmm)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;
	unsigned long req_block = blocknr;
	struct pmfs_inode_entry *entry;
	struct mem_addr *pair;

	height = pi->height;
	bp = le64_to_cpu(pi->root);
	if (bp == 0)
		return 0;

	while (height > 0) {
		level_ptr = (__le64 *)DRAM_ADDR(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}

	pair = (struct mem_addr *)bp;

	if (nvmm) {
		entry = (struct pmfs_inode_entry *)
					pmfs_get_block(sb, pair->nvmm);
		pmfs_dbg_verbose("%s: %lu, entry pgoff %u, num %u, "
			"blocknr %llu\n", __func__, req_block, entry->pgoff,
			entry->num_pages, entry->block >> PAGE_SHIFT);
		if (req_block < entry->pgoff ||
			 req_block - entry->pgoff >= entry->num_pages) {
			pmfs_err(sb, "%s ERROR: %lu, entry pgoff %u, num %u, "
				"blocknr %llu\n", __func__, req_block,
				entry->pgoff, entry->num_pages,
				entry->block >> PAGE_SHIFT);
			return 0;
		}
		return BLOCK_OFF(entry->block +
				((req_block - entry->pgoff) << PAGE_SHIFT));
	} else {
		return pair->dram;
	}
}

static inline u64 __pmfs_find_dir_block(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);
	if (bp == 0)
		return 0;

	while (height > 0) {
		level_ptr = (__le64 *)DRAM_ADDR(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}

	return bp;
}

/* Return 1 if the page is found and dirty */
static inline int pmfs_find_dram_page_and_clean(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr, u64 *dram_addr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;
	struct mem_addr *pair;

	height = pi->height;
	bp = le64_to_cpu(pi->root);
	if (bp == 0)
		return 0;

	while (height > 0) {
		level_ptr = (__le64 *)DRAM_ADDR(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return 0;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}

	pair = (struct mem_addr *)bp;
	if (pair->dram && IS_DIRTY(pair->dram)) {
		*dram_addr = pair->dram;
		pair->dram &= ~DIRTY_BIT;
		return 1;
	}

	return 0;
}

static inline struct mem_addr *__pmfs_get_entry(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long blocknr)
{
	__le64 *level_ptr;
	u64 bp = 0;
	u32 height, bit_shift;
	unsigned int idx;

	height = pi->height;
	bp = le64_to_cpu(pi->root);
	if (bp == 0)
		return NULL;

	pmfs_dbg_verbose("%s: height %u, root 0x%llx\n", __func__, height, bp);
	while (height > 0) {
		level_ptr = (__le64 *)DRAM_ADDR(bp);
		bit_shift = (height - 1) * META_BLK_SHIFT;
		idx = blocknr >> bit_shift;
		bp = le64_to_cpu(level_ptr[idx]);
		if (bp == 0)
			return NULL;
		blocknr = blocknr & ((1 << bit_shift) - 1);
		height--;
	}

	return (struct mem_addr *)bp;
#if 0
	entry = (struct pmfs_inode_entry *)pmfs_get_block(sb, bp);
	pmfs_dbg_verbose("%s: %lu, entry pgoff %u, num %u, blocknr %llu\n",
		__func__, req_block, entry->pgoff, entry->num_pages,
		entry->block >> PAGE_SHIFT);
	if (req_block < entry->pgoff ||
			 req_block - entry->pgoff >= entry->num_pages) {
		pmfs_err(sb, "%s ERROR: %lu, entry pgoff %u, num %u, blocknr "
			"%llu\n", __func__, req_block, entry->pgoff,
			entry->num_pages, entry->block >> PAGE_SHIFT);
		return NULL;
	}
	return entry;
#endif
}

static inline unsigned int pmfs_inode_blk_shift (struct pmfs_inode *pi)
{
	return blk_type_to_shift[pi->i_blk_type];
}

static inline uint32_t pmfs_inode_blk_size (struct pmfs_inode *pi)
{
	return blk_type_to_size[pi->i_blk_type];
}

/* If this is part of a read-modify-write of the inode metadata,
 * pmfs_memunlock_inode() before calling! */
static inline struct pmfs_inode *pmfs_get_inode(struct super_block *sb,
						  u64	ino)
{
	struct pmfs_super_block *ps = pmfs_get_super(sb);
	struct pmfs_inode *inode_table = pmfs_get_inode_table(sb);
	u64 bp, block, ino_offset;

	if (ino == 0)
		return NULL;

	block = ino >> pmfs_inode_blk_shift(inode_table);
	bp = __pmfs_find_inode(sb, inode_table, block);

	if (bp == 0)
		return NULL;
	ino_offset = (ino & (pmfs_inode_blk_size(inode_table) - 1));
	return (struct pmfs_inode *)((void *)ps + bp + ino_offset);
}

static inline u64
pmfs_get_addr_off(struct pmfs_sb_info *sbi, void *addr)
{
	PMFS_ASSERT((addr >= sbi->virt_addr) &&
			(addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline u64
pmfs_get_block_off(struct super_block *sb, unsigned long blocknr,
		    unsigned short btype)
{
	return (u64)blocknr << PAGE_SHIFT;
}

static inline unsigned long
pmfs_get_numblocks(unsigned short btype)
{
	unsigned long num_blocks;

	if (btype == PMFS_BLOCK_TYPE_4K) {
		num_blocks = 1;
	} else if (btype == PMFS_BLOCK_TYPE_2M) {
		num_blocks = 512;
	} else {
		//btype == PMFS_BLOCK_TYPE_1G 
		num_blocks = 0x40000;
	}
	return num_blocks;
}

static inline unsigned long
pmfs_get_blocknr(struct super_block *sb, u64 block, unsigned short btype)
{
	return block >> PAGE_SHIFT;
}

static inline unsigned long pmfs_get_pfn(struct super_block *sb, u64 block)
{
	return (PMFS_SB(sb)->phys_addr + block) >> PAGE_SHIFT;
}

static inline int pmfs_is_mounting(struct super_block *sb)
{
	struct pmfs_sb_info *sbi = (struct pmfs_sb_info *)sb->s_fs_info;
	return sbi->s_mount_opt & PMFS_MOUNT_MOUNTING;
}

static inline struct pmfs_inode_truncate_item * pmfs_get_truncate_item (struct 
		super_block *sb, u64 ino)
{
	struct pmfs_inode *pi = pmfs_get_inode(sb, ino);
	return (struct pmfs_inode_truncate_item *)(pi + 1);
}

static inline struct pmfs_inode_truncate_item * pmfs_get_truncate_list_head (
		struct super_block *sb)
{
	struct pmfs_inode *pi = pmfs_get_inode_table(sb);
	return (struct pmfs_inode_truncate_item *)(pi + 1);
}

static inline void check_eof_blocks(struct super_block *sb, 
		struct pmfs_inode *pi, loff_t size)
{
	if ((pi->i_flags & cpu_to_le32(PMFS_EOFBLOCKS_FL)) &&
		(size + sb->s_blocksize) > (le64_to_cpu(pi->i_blocks)
			<< sb->s_blocksize_bits))
		pi->i_flags &= cpu_to_le32(~PMFS_EOFBLOCKS_FL);
}

#include "wprotect.h"

/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations pmfs_dir_operations;
void pmfs_rebuild_root_dir(struct super_block *sb, struct pmfs_inode *root_pi);
void pmfs_print_dir_tree(struct super_block *sb, struct inode *inode);
void pmfs_delete_dir_tree(struct super_block *sb, struct inode *inode);
int pmfs_insert_dir_node_by_name(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, const char *name, int namelen, u64 dir_entry);
struct pmfs_dir_node *pmfs_find_dir_node_by_name(struct super_block *sb,
	struct pmfs_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len);

/* file.c */
extern const struct inode_operations pmfs_file_inode_operations;
extern const struct file_operations pmfs_xip_file_operations;
int pmfs_fsync(struct file *file, loff_t start, loff_t end, int datasync);

/* inode.c */
static inline u64 next_log_page(struct super_block *sb, u64 curr_p)
{
	void *curr_addr = pmfs_get_block(sb, curr_p);
	unsigned long page_tail = ((unsigned long)curr_addr & ~INVALID_MASK)
					+ LAST_ENTRY;
	return ((struct pmfs_inode_page_tail *)page_tail)->next_page;
}

static inline bool is_last_entry(u64 curr_p, size_t size)
{
	return ENTRY_LOC(curr_p) + size > LAST_ENTRY;
}

static inline bool is_last_dir_entry(struct super_block *sb, u64 curr_p)
{
	struct pmfs_log_direntry *entry;

	if (ENTRY_LOC(curr_p) + PMFS_DIR_LOG_REC_LEN(0) > LAST_ENTRY)
		return true;

	entry = (struct pmfs_log_direntry *)pmfs_get_block(sb, curr_p);
	if (entry->name_len == 0)
		return true;
	return false;
}

static inline int is_dir_init_entry(struct super_block *sb,
	struct pmfs_log_direntry *entry)
{
	if (entry->name_len == 1 && strncmp(entry->name, ".", 1) == 0)
		return 1;
	if (entry->name_len == 2 && strncmp(entry->name, "..", 2) == 0)
		return 1;

	return 0;
}

extern const struct address_space_operations pmfs_aops_xip;
u64 pmfs_append_file_inode_entry(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, struct pmfs_inode_entry *data, u64 tail);
u64 pmfs_append_dir_inode_entry(struct super_block *sb, struct pmfs_inode *pi,
	struct inode *inode, u64 ino, struct dentry *dentry,
	unsigned short de_len, u64 tail, int link_change);
int pmfs_append_dir_init_entries(struct super_block *sb,
	struct pmfs_inode *pi, struct inode *inode, u64 parent_ino);
void pmfs_free_dram_pages(struct super_block *sb);
int pmfs_rebuild_file_inode_tree(struct super_block *sb, struct inode *inode,
	struct pmfs_inode *pi);
struct mem_addr *pmfs_get_mem_pair(struct super_block *sb,
		struct pmfs_inode *pi, unsigned long file_blocknr);

/* bbuild.c */
void pmfs_save_blocknode_mappings(struct super_block *sb);

/* namei.c */
extern const struct inode_operations pmfs_dir_inode_operations;
extern const struct inode_operations pmfs_special_inode_operations;

/* symlink.c */
extern const struct inode_operations pmfs_symlink_inode_operations;

int pmfs_check_integrity(struct super_block *sb,
	struct pmfs_super_block *super);
void *pmfs_ioremap(struct super_block *sb, phys_addr_t phys_addr,
	ssize_t size);

int pmfs_check_dir_entry(const char *function, struct inode *dir,
			  struct pmfs_direntry *de, u8 *base,
			  unsigned long offset);

static inline int pmfs_match(int len, const char *const name,
			      struct pmfs_direntry *de)
{
	if (len == de->name_len && de->ino && !memcmp(de->name, name, len))
		return 1;
	return 0;
}

/* xip.c */
ssize_t pmfs_cow_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos, bool need_mutex);
int pmfs_copy_to_nvmm(struct inode *inode, pgoff_t pgoff, loff_t offset,
				unsigned long count);

/* pmfs_stats.c */
void pmfs_print_timing_stats(struct super_block *sb);
void pmfs_clear_stats(void);
void pmfs_print_inode_log(struct super_block *sb, struct inode *inode);
void pmfs_print_inode_log_page(struct super_block *sb, struct inode *inode);
void pmfs_print_inode_log_blocknode(struct super_block *sb, struct inode *inode);

#endif /* __PMFS_H */
