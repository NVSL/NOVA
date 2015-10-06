/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright 2015 NVSL, UC San Diego
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

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/backing-dev.h>
#include <linux/list.h>
#include "nova.h"

int measure_timing = 0;
int support_clwb = 0;
int support_pcommit = 0;

module_param(measure_timing, int, S_IRUGO);
MODULE_PARM_DESC(measure_timing, "Timing measurement");

static struct super_operations nova_sops;
static const struct export_operations nova_export_ops;
static struct kmem_cache *nova_inode_cachep;
static struct kmem_cache *nova_range_node_cachep;

/* FIXME: should the following variable be one per NOVA instance? */
unsigned int nova_dbgmask = 0;

void nova_error_mng(struct super_block *sb, const char *fmt, ...)
{
	va_list args;

	printk("nova error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	if (test_opt(sb, ERRORS_PANIC))
		panic("nova: panic from previous error\n");
	if (test_opt(sb, ERRORS_RO)) {
		printk(KERN_CRIT "nova err: remounting filesystem read-only");
		sb->s_flags |= MS_RDONLY;
	}
}

static void nova_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	/*
	 * We've already validated the user input and the value here must be
	 * between NOVA_MAX_BLOCK_SIZE and NOVA_MIN_BLOCK_SIZE
	 * and it must be a power of 2.
	 */
	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

void *nova_ioremap(struct super_block *sb, phys_addr_t phys_addr, ssize_t size)
{
	void __iomem *retval;
	int protect;
	timing_t remap_time;

	NOVA_START_TIMING(ioremap_t, remap_time);
	if (sb) {
		protect = nova_is_wprotected(sb);
	} else {
		protect = 0;
	}

	/*
	 * NOTE: Userland may not map this resource, we will mark the region so
	 * /dev/mem and the sysfs MMIO access will not be allowed. This
	 * restriction depends on STRICT_DEVMEM option. If this option is
	 * disabled or not available we mark the region only as busy.
	 */
	retval = (void __iomem *)
			request_mem_region_exclusive(phys_addr, size, "nova");
	if (!retval)
		goto fail;

	if (protect) {
		/* FIXME: ioremap_cache_ro not support in 4.2 */
		retval = ioremap_cache(phys_addr, size);
	} else {
		retval = ioremap_cache(phys_addr, size);
	}

fail:
	NOVA_END_TIMING(ioremap_t, remap_time);
	return (void __force *)retval;
}

static inline int nova_iounmap(void *virt_addr, ssize_t size, int protected)
{
	iounmap((void __iomem __force *)virt_addr);
	return 0;
}

static loff_t nova_max_size(int bits)
{
	loff_t res;

	res = (1ULL << (3 * 9 + bits)) - 1;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	nova_dbg_verbose("max file size %llu bytes\n", res);
	return res;
}

enum {
	Opt_addr, Opt_bpi, Opt_size,
	Opt_mode, Opt_uid,
	Opt_gid, Opt_blocksize, Opt_wprotect,
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_dbgmask, Opt_err
};

static const match_table_t tokens = {
	{ Opt_addr,	     "physaddr=%x"	  },
	{ Opt_bpi,	     "bpi=%u"		  },
	{ Opt_size,	     "init=%s"		  },
	{ Opt_mode,	     "mode=%o"		  },
	{ Opt_uid,	     "uid=%u"		  },
	{ Opt_gid,	     "gid=%u"		  },
	{ Opt_wprotect,	     "wprotect"		  },
	{ Opt_err_cont,	     "errors=continue"	  },
	{ Opt_err_panic,     "errors=panic"	  },
	{ Opt_err_ro,	     "errors=remount-ro"  },
	{ Opt_dbgmask,	     "dbgmask=%u"	  },
	{ Opt_err,	     NULL		  },
};

static phys_addr_t get_phys_addr(void **data)
{
	phys_addr_t phys_addr;
	char *options = (char *)*data;

	if (!options || strncmp(options, "physaddr=", 9) != 0)
		return (phys_addr_t)ULLONG_MAX;
	options += 9;
	phys_addr = (phys_addr_t)simple_strtoull(options, &options, 0);
	if (*options && *options != ',') {
		printk(KERN_ERR "Invalid phys addr specification: %s\n",
		       (char *)*data);
		return (phys_addr_t)ULLONG_MAX;
	}
	if (phys_addr & (PAGE_SIZE - 1)) {
		printk(KERN_ERR "physical address 0x%16llx for nova isn't "
		       "aligned to a page boundary\n", (u64)phys_addr);
		return (phys_addr_t)ULLONG_MAX;
	}
	if (*options == ',')
		options++;
	*data = (void *)options;
	return phys_addr;
}

static int nova_parse_options(char *options, struct nova_sb_info *sbi,
			       bool remount)
{
	char *p, *rest;
	substring_t args[MAX_OPT_ARGS];
	int option;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_addr:
			if (remount)
				goto bad_opt;
			/* physaddr managed in get_phys_addr() */
			break;
		case Opt_bpi:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->bpi = option;
			break;
		case Opt_uid:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->uid = make_kuid(current_user_ns(), option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				goto bad_val;
			sbi->mode = option & 01777U;
			break;
		case Opt_size:
			if (remount)
				goto bad_opt;
			/* memparse() will accept a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			sbi->initsize = memparse(args[0].from, &rest);
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_err_panic:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_RO);
			break;
		case Opt_err_cont:
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_wprotect:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, PROTECT);
			nova_info("NOVA: Enabling new Write Protection "
				"(CR0.WP)\n");
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad_val;
			nova_dbgmask = option;
			break;
		default: {
			goto bad_opt;
		}
		}
	}

	return 0;

bad_val:
	printk(KERN_INFO "Bad value '%s' for mount option '%s'\n", args[0].from,
	       p);
	return -EINVAL;
bad_opt:
	printk(KERN_INFO "Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}

static bool nova_check_size(struct super_block *sb, unsigned long size)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long minimum_size, num_blocks;

	/* space required for super block and root directory */
	minimum_size = 2 << sb->s_blocksize_bits;

	/* space required for inode table */
	if (sbi->num_inodes > 0)
		num_blocks = (sbi->num_inodes >>
			(sb->s_blocksize_bits - NOVA_INODE_BITS)) + 1;
	else
		num_blocks = 1;
	minimum_size += (num_blocks << sb->s_blocksize_bits);

	if (size < minimum_size)
	    return false;

	return true;
}


static struct nova_inode *nova_init(struct super_block *sb,
				      unsigned long size)
{
	unsigned long blocksize;
	u64 inode_table_start;
	unsigned long reserved_space, reserved_blocks;
	struct nova_inode *root_i;
	struct nova_super_block *super;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	timing_t init_time;

	NOVA_START_TIMING(new_init_t, init_time);
	nova_info("creating an empty nova of size %lu\n", size);
	sbi->virt_addr = nova_ioremap(sb, sbi->phys_addr, size);
	sbi->block_start = (unsigned long)0;
	sbi->block_end = ((unsigned long)(size) >> PAGE_SHIFT);

	if (!sbi->virt_addr) {
		printk(KERN_ERR "ioremap of the nova image failed(1)\n");
		return ERR_PTR(-EINVAL);
	}

	nova_dbg_verbose("nova: Default block size set to 4K\n");
	blocksize = sbi->blocksize = NOVA_DEF_BLOCK_SIZE_4K;

	nova_set_blocksize(sb, blocksize);
	blocksize = sb->s_blocksize;

	if (sbi->blocksize && sbi->blocksize != blocksize)
		sbi->blocksize = blocksize;

	if (!nova_check_size(sb, size)) {
		nova_dbg("Specified NOVA size too small 0x%lx.\n", size);
		return ERR_PTR(-EINVAL);
	}

	inode_table_start = sizeof(struct nova_super_block);
	inode_table_start = (inode_table_start + CACHELINE_SIZE - 1) &
		~(CACHELINE_SIZE - 1);

	if ((inode_table_start + sizeof(struct nova_inode)) > NOVA_SB_SIZE) {
		nova_dbg("NOVA super block defined too small. defined 0x%x, "
				"required 0x%llx\n", NOVA_SB_SIZE,
			inode_table_start + sizeof(struct nova_inode));
		return ERR_PTR(-EINVAL);
	}

	/* Reserve space for 8 special inodes */
	reserved_space = NOVA_SB_SIZE * 4;
	reserved_blocks = (reserved_space + blocksize - 1) / blocksize;
	if (reserved_blocks > sbi->reserved_blocks) {
		nova_dbg("Reserved %lu blocks, require %lu blocks. "
			"Increase reserved blocks number.\n",
			sbi->reserved_blocks, reserved_blocks);
		return ERR_PTR(-EINVAL);
	}

	nova_dbg_verbose("max file name len %d\n", (unsigned int)NOVA_NAME_LEN);

	super = nova_get_super(sb);

	/* clear out super-block and inode table */
	memset_nt(super, 0, reserved_space);
	super->s_size = cpu_to_le64(size);
	super->s_blocksize = cpu_to_le32(blocksize);
	super->s_magic = cpu_to_le32(NOVA_SUPER_MAGIC);
	super->s_inode_table_offset = cpu_to_le64(inode_table_start);

	nova_init_blockmap(sb, 0);

	if (nova_lite_journal_hard_init(sb) < 0) {
		printk(KERN_ERR "Lite journal hard initialization failed\n");
		return ERR_PTR(-EINVAL);
	}

	if (nova_init_inode_table(sb) < 0)
		return ERR_PTR(-EINVAL);

	nova_memunlock_range(sb, super, NOVA_SB_SIZE*2);
	nova_sync_super(super);
	nova_memlock_range(sb, super, NOVA_SB_SIZE*2);

	nova_flush_buffer(super, NOVA_SB_SIZE, false);
	nova_flush_buffer((char *)super + NOVA_SB_SIZE, sizeof(*super), false);

	nova_dbg_verbose("Allocate root inode\n");
	root_i = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	nova_memunlock_inode(sb, root_i);
	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_blk_type = NOVA_BLOCK_TYPE_4K;
	root_i->i_flags = 0;
	root_i->i_blocks = cpu_to_le64(1);
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->nova_ino = 1;
	root_i->valid = 1;
	/* nova_sync_inode(root_i); */
	nova_memlock_inode(sb, root_i);
	nova_flush_buffer(root_i, sizeof(*root_i), false);

	nova_append_dir_init_entries(sb, root_i, NOVA_ROOT_INO,
					NOVA_ROOT_INO);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(new_init_t, init_time);
	return root_i;
}

static inline void set_default_opts(struct nova_sb_info *sbi)
{
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);
	set_opt(sbi->s_mount_opt, ERRORS_CONT);
	sbi->reserved_blocks = RESERVED_BLOCKS;
}

static void nova_root_check(struct super_block *sb, struct nova_inode *root_pi)
{
/*
 *      if (root_pi->i_d.d_next) {
 *              nova_warn("root->next not NULL, trying to fix\n");
 *              goto fail1;
 *      }
 */
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
		nova_warn("root is not a directory!\n");
#if 0
	if (nova_calc_checksum((u8 *)root_pi, NOVA_INODE_SIZE)) {
		nova_dbg("checksum error in root inode, trying to fix\n");
		goto fail3;
	}
#endif
}

int nova_check_integrity(struct super_block *sb,
			  struct nova_super_block *super)
{
	struct nova_super_block *super_redund;

	super_redund =
		(struct nova_super_block *)((char *)super + NOVA_SB_SIZE);

	/* Do sanity checks on the superblock */
	if (le32_to_cpu(super->s_magic) != NOVA_SUPER_MAGIC) {
		if (le32_to_cpu(super_redund->s_magic) != NOVA_SUPER_MAGIC) {
			printk(KERN_ERR "Can't find a valid nova partition\n");
			goto out;
		} else {
			nova_warn
				("Error in super block: try to repair it with "
				"the redundant copy");
			/* Try to auto-recover the super block */
			if (sb)
				nova_memunlock_super(sb, super);
			memcpy(super, super_redund,
				sizeof(struct nova_super_block));
			if (sb)
				nova_memlock_super(sb, super);
			nova_flush_buffer(super, sizeof(*super), false);
			nova_flush_buffer((char *)super + NOVA_SB_SIZE,
				sizeof(*super), false);

		}
	}

	/* Read the superblock */
	if (nova_calc_checksum((u8 *)super, NOVA_SB_STATIC_SIZE(super))) {
		if (nova_calc_checksum((u8 *)super_redund,
					NOVA_SB_STATIC_SIZE(super_redund))) {
			printk(KERN_ERR "checksum error in super block\n");
			goto out;
		} else {
			nova_warn
				("Error in super block: try to repair it with "
				"the redundant copy");
			/* Try to auto-recover the super block */
			if (sb)
				nova_memunlock_super(sb, super);
			memcpy(super, super_redund,
				sizeof(struct nova_super_block));
			if (sb)
				nova_memlock_super(sb, super);
			nova_flush_buffer(super, sizeof(*super), false);
			nova_flush_buffer((char *)super + NOVA_SB_SIZE,
				sizeof(*super), false);
		}
	}

	return 1;
out:
	return 0;
}

static int nova_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nova_super_block *super;
	struct nova_inode *root_pi;
	struct nova_sb_info *sbi = NULL;
	struct inode *root_i = NULL;
	unsigned long blocksize, initsize = 0;
	u32 random = 0;
	int retval = -EINVAL;
	timing_t mount_time;

	NOVA_START_TIMING(mount_t, mount_time);

	BUILD_BUG_ON(sizeof(struct nova_super_block) > NOVA_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct nova_inode) > NOVA_INODE_SIZE);
	BUILD_BUG_ON(sizeof(struct nova_inode_log_page) != PAGE_SIZE);

	if (arch_has_pcommit()) {
		nova_info("arch has PCOMMIT support\n");
		support_pcommit = 1;
	} else {
		nova_info("arch does not have PCOMMIT support\n");
	}

	if (arch_has_clwb()) {
		nova_info("arch has CLWB support\n");
		support_clwb = 1;
	} else {
		nova_info("arch does not have CLWB support\n");
	}

	nova_dbg("Data structure size: inode %lu, log_page %lu, "
		"file_write_entry %lu, dir_entry(max) %lu, "
		"setattr_entry %lu, link_change_entry %lu\n",
		sizeof(struct nova_inode),
		sizeof(struct nova_inode_log_page),
		sizeof(struct nova_file_write_entry),
		sizeof(struct nova_dir_logentry),
		sizeof(struct nova_setattr_logentry),
		sizeof(struct nova_link_change_entry));

	sbi = kzalloc(sizeof(struct nova_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	set_default_opts(sbi);

	sbi->phys_addr = get_phys_addr(&data);
	if (sbi->phys_addr == (phys_addr_t)ULLONG_MAX)
		goto out;

	get_random_bytes(&random, sizeof(u32));
	atomic_set(&sbi->next_generation, random);

	/* Init with default values */
	INIT_RADIX_TREE(&sbi->header_tree, GFP_ATOMIC);
	sbi->shared_free_list.block_free_tree = RB_ROOT;
	spin_lock_init(&sbi->shared_free_list.s_lock);
	sbi->mode = (S_IRUGO | S_IXUGO | S_IWUSR);
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	set_opt(sbi->s_mount_opt, DAX);
	clear_opt(sbi->s_mount_opt, PROTECT);
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);

	mutex_init(&sbi->inode_table_mutex);
	mutex_init(&sbi->s_lock);

	sbi->inode_inuse_tree = RB_ROOT;

	sbi->zeroed_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sbi->zeroed_page)
		goto out;

	if (nova_parse_options(data, sbi, 0))
		goto out;

	set_opt(sbi->s_mount_opt, MOUNTING);
	initsize = sbi->initsize;

	if (nova_alloc_block_free_lists(sb))
		goto out;

	/* Init a new nova instance */
	if (initsize) {
		root_pi = nova_init(sb, initsize);
		if (IS_ERR(root_pi))
			goto out;
		super = nova_get_super(sb);
		goto setup_sb;
	}
	nova_dbg_verbose("checking physical address 0x%016llx for nova image\n",
		  (u64)sbi->phys_addr);

	/* Map only one page for now. Will remap it when fs size is known. */
	initsize = PAGE_SIZE;
	sbi->virt_addr = nova_ioremap(sb, sbi->phys_addr, initsize);
	if (!sbi->virt_addr) {
		printk(KERN_ERR "ioremap of the nova image failed(2)\n");
		goto out;
	}

	super = nova_get_super(sb);

	initsize = le64_to_cpu(super->s_size);
	sbi->initsize = initsize;
	nova_dbg_verbose("nova image appears to be %lu KB in size\n",
		   initsize >> 10);

	nova_iounmap(sbi->virt_addr, PAGE_SIZE, nova_is_wprotected(sb));

	/* Remap the whole filesystem now */
	release_mem_region(sbi->phys_addr, PAGE_SIZE);
	/* FIXME: Remap the whole filesystem in nova virtual address range. */
	sbi->virt_addr = nova_ioremap(sb, sbi->phys_addr, initsize);
	if (!sbi->virt_addr) {
		printk(KERN_ERR "ioremap of the nova image failed(3)\n");
		goto out;
	}

	super = nova_get_super(sb);

	if (nova_lite_journal_soft_init(sb)) {
		retval = -EINVAL;
		printk(KERN_ERR "Lite journal initialization failed\n");
		goto out;
	}

	if (nova_check_integrity(sb, super) == 0) {
		nova_dbg("Memory contains invalid nova %x:%x\n",
				le32_to_cpu(super->s_magic), NOVA_SUPER_MAGIC);
		goto out;
	}

	blocksize = le32_to_cpu(super->s_blocksize);
	nova_set_blocksize(sb, blocksize);

	nova_dbg_verbose("blocksize %lu\n", blocksize);

	/* Read the root inode */
	root_pi = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	/* Check that the root inode is in a sane state */
	nova_root_check(sb, root_pi);

	/* Set it all up.. */
setup_sb:
	sb->s_magic = le32_to_cpu(super->s_magic);
	sb->s_op = &nova_sops;
	sb->s_maxbytes = nova_max_size(sb->s_blocksize_bits);
	sb->s_time_gran = 1;
	sb->s_export_op = &nova_export_ops;
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

	/* If the FS was not formatted on this mount, scan the meta-data after
	 * truncate list has been processed */
	if ((sbi->s_mount_opt & NOVA_MOUNT_FORMAT) == 0)
		nova_inode_log_recovery(sb, 1);

	root_i = nova_iget(sb, NOVA_ROOT_INO);
	if (IS_ERR(root_i)) {
		retval = PTR_ERR(root_i);
		goto out;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		printk(KERN_ERR "get nova root inode failed\n");
		retval = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		u64 mnt_write_time;
		/* update mount time and write time atomically. */
		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		nova_memunlock_range(sb, &super->s_mtime, 8);
		nova_memcpy_atomic(&super->s_mtime, &mnt_write_time, 8);
		nova_memlock_range(sb, &super->s_mtime, 8);

		nova_flush_buffer(&super->s_mtime, 8, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}

	clear_opt(sbi->s_mount_opt, MOUNTING);
	retval = 0;

	NOVA_END_TIMING(mount_t, mount_time);
	return retval;
out:
	if (sbi->virt_addr) {
		nova_iounmap(sbi->virt_addr, initsize, nova_is_wprotected(sb));
		release_mem_region(sbi->phys_addr, initsize);
	}

	if (sbi->zeroed_page) {
		kfree(sbi->zeroed_page);
		sbi->zeroed_page = NULL;
	}

	if (sbi->free_lists) {
		kfree(sbi->free_lists);
		sbi->free_lists = NULL;
	}

	kfree(sbi);
	return retval;
}

int nova_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	unsigned long count = 0;
	struct nova_sb_info *sbi = (struct nova_sb_info *)sb->s_fs_info;

	buf->f_type = NOVA_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;

	count = sbi->block_end;
	buf->f_blocks = sbi->block_end;
	buf->f_bfree = buf->f_bavail = nova_count_free_blocks(sb);
	buf->f_files = LONG_MAX;
	buf->f_ffree = LONG_MAX - sbi->s_inodes_used_count;
	buf->f_namelen = NOVA_NAME_LEN;
	nova_dbg_verbose("nova_stats: total 4k free blocks 0x%llx\n",
		buf->f_bfree);
	return 0;
}

static int nova_show_options(struct seq_file *seq, struct dentry *root)
{
	struct nova_sb_info *sbi = NOVA_SB(root->d_sb);

	seq_printf(seq, ",physaddr=0x%016llx", (u64)sbi->phys_addr);
	if (sbi->initsize)
		seq_printf(seq, ",init=%luk", sbi->initsize >> 10);
	if (sbi->blocksize)
		seq_printf(seq, ",bs=%lu", sbi->blocksize);
	if (sbi->bpi)
		seq_printf(seq, ",bpi=%lu", sbi->bpi);
	if (sbi->num_inodes)
		seq_printf(seq, ",N=%lu", sbi->num_inodes);
	if (sbi->mode != (S_IRWXUGO | S_ISVTX))
		seq_printf(seq, ",mode=%03o", sbi->mode);
	if (uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
	if (gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
	if (test_opt(root->d_sb, ERRORS_RO))
		seq_puts(seq, ",errors=remount-ro");
	if (test_opt(root->d_sb, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	/* memory protection disabled by default */
	if (test_opt(root->d_sb, PROTECT))
		seq_puts(seq, ",wprotect");
	if (test_opt(root->d_sb, DAX))
		seq_puts(seq, ",dax");

	return 0;
}

int nova_remount(struct super_block *sb, int *mntflags, char *data)
{
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	struct nova_super_block *ps;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret = -EINVAL;

	/* Store the old options */
	mutex_lock(&sbi->s_lock);
	old_sb_flags = sb->s_flags;
	old_mount_opt = sbi->s_mount_opt;

	if (nova_parse_options(data, sbi, 1))
		goto restore_opt;

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		      ((sbi->s_mount_opt & NOVA_MOUNT_POSIX_ACL) ? MS_POSIXACL : 0);

	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
		u64 mnt_write_time;
		ps = nova_get_super(sb);
		/* update mount time and write time atomically. */
		mnt_write_time = (get_seconds() & 0xFFFFFFFF);
		mnt_write_time = mnt_write_time | (mnt_write_time << 32);

		nova_memunlock_range(sb, &ps->s_mtime, 8);
		nova_memcpy_atomic(&ps->s_mtime, &mnt_write_time, 8);
		nova_memlock_range(sb, &ps->s_mtime, 8);

		nova_flush_buffer(&ps->s_mtime, 8, false);
		PERSISTENT_MARK();
		PERSISTENT_BARRIER();
	}

	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;

restore_opt:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_mount_opt;
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static void nova_put_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *ps = nova_get_super(sb);
	u64 size = le64_to_cpu(ps->s_size);

	/* It's unmount time, so unmap the nova memory */
//	nova_print_free_lists(sb);
	if (sbi->virt_addr) {
		nova_free_header_tree(sb);
		nova_save_inode_list_to_log(sb);
		/* Save everything before blocknode mapping! */
		nova_save_blocknode_mappings_to_log(sb);
		nova_iounmap(sbi->virt_addr, size, nova_is_wprotected(sb));
		sbi->virt_addr = NULL;
		release_mem_region(sbi->phys_addr, size);
	}

	nova_delete_free_lists(sb);

	kfree(sbi->zeroed_page);
	nova_detect_memory_leak(sb);
	sb->s_fs_info = NULL;
	nova_dbgmask = 0;
	kfree(sbi);
}

inline void nova_free_range_node(struct nova_range_node *node)
{
	kmem_cache_free(nova_range_node_cachep, node);
	atomic64_inc(&range_free);
}

inline void nova_free_blocknode(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}

inline void nova_free_inode_node(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}

static inline
struct nova_range_node *nova_alloc_range_node(struct super_block *sb)
{
	struct nova_range_node *p;
	p = (struct nova_range_node *)
		kmem_cache_alloc(nova_range_node_cachep, GFP_NOFS);
	atomic64_inc(&range_alloc);
	return p;
}

inline struct nova_range_node *nova_alloc_blocknode(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

inline struct nova_range_node *nova_alloc_inode_node(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

static struct inode *nova_alloc_inode(struct super_block *sb)
{
	struct nova_inode_info *vi;

	vi = kmem_cache_alloc(nova_inode_cachep, GFP_NOFS);
	if (!vi)
		return NULL;

	vi->header = NULL;
	vi->low_mmap = ULONG_MAX;
	vi->high_mmap = 0;
	vi->vfs_inode.i_version = 1;

	return &vi->vfs_inode;
}

static void nova_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct nova_inode_info *vi = NOVA_I(inode);

	nova_dbg_verbose("%s: ino %lu\n", __func__, inode->i_ino);
	kmem_cache_free(nova_inode_cachep, vi);
}

static void nova_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, nova_i_callback);
}

static void init_once(void *foo)
{
	struct nova_inode_info *vi = foo;

	vi->header = NULL;
	vi->i_dir_start_lookup = 0;
	inode_init_once(&vi->vfs_inode);
}


static int __init init_rangenode_cache(void)
{
	nova_range_node_cachep = kmem_cache_create("nova_range_node_cache",
					sizeof(struct nova_range_node),
					0, (SLAB_RECLAIM_ACCOUNT |
                                        SLAB_MEM_SPREAD), NULL);
	if (nova_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}


static int __init init_inodecache(void)
{
	nova_inode_cachep = kmem_cache_create("nova_inode_cache",
					       sizeof(struct nova_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), init_once);
	if (nova_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static int __init init_header_cache(void)
{
	nova_header_cachep = kmem_cache_create("nova_header_cache",
					sizeof(struct nova_inode_info_header),
					0, (SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD), NULL);
	if (nova_header_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(nova_inode_cachep);
}

static void destroy_header_cache(void)
{
	kmem_cache_destroy(nova_header_cachep);
}

static void destroy_rangenode_cache(void)
{
	kmem_cache_destroy(nova_range_node_cachep);
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations nova_sops = {
	.alloc_inode	= nova_alloc_inode,
	.destroy_inode	= nova_destroy_inode,
	.write_inode	= nova_write_inode,
	.dirty_inode	= nova_dirty_inode,
	.evict_inode	= nova_evict_inode,
	.put_super	= nova_put_super,
	.statfs		= nova_statfs,
	.remount_fs	= nova_remount,
	.show_options	= nova_show_options,
};

static struct dentry *nova_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, nova_fill_super);
}

static struct file_system_type nova_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "NOVA",
	.mount		= nova_mount,
	.kill_sb	= kill_anon_super,
};

static struct inode *nova_nfs_get_inode(struct super_block *sb,
					 u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino < NOVA_ROOT_INO)
		return ERR_PTR(-ESTALE);

	if (ino > LONG_MAX)
		return ERR_PTR(-ESTALE);

	inode = nova_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (generation && inode->i_generation != generation) {
		/* we didn't find the right inode.. */
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *nova_fh_to_dentry(struct super_block *sb,
					 struct fid *fid, int fh_len,
					 int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    nova_nfs_get_inode);
}

static struct dentry *nova_fh_to_parent(struct super_block *sb,
					 struct fid *fid, int fh_len,
					 int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    nova_nfs_get_inode);
}

static const struct export_operations nova_export_ops = {
	.fh_to_dentry	= nova_fh_to_dentry,
	.fh_to_parent	= nova_fh_to_parent,
	.get_parent	= nova_get_parent,
};

static int __init init_nova_fs(void)
{
	int rc = 0;
	timing_t init_time;

	NOVA_START_TIMING(init_t, init_time);
	rc = init_rangenode_cache();
	if (rc)
		return rc;

	rc = init_inodecache();
	if (rc)
		goto out1;

	rc = init_header_cache();
	if (rc)
		goto out2;

	rc = register_filesystem(&nova_fs_type);
	if (rc)
		goto out3;

	NOVA_END_TIMING(init_t, init_time);
	return 0;

out3:
	destroy_header_cache();
out2:
	destroy_inodecache();
out1:
	destroy_rangenode_cache();
	return rc;
}

static void __exit exit_nova_fs(void)
{
	unregister_filesystem(&nova_fs_type);
	destroy_inodecache();
	destroy_rangenode_cache();
	destroy_header_cache();
}

MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("NOVA: A Persistent Memory File System");
MODULE_LICENSE("GPL");

module_init(init_nova_fs)
module_exit(exit_nova_fs)
