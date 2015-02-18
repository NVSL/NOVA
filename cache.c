#include <linux/time.h>
#include <linux/fs.h>
#include <linux/blkdev.h>

#include "pmfs.h"

static int pmfs_cache_init_backing_dev(struct pmfs_cache_info *cinfo,
					char *backing_dev_path)
{
	struct block_device *bdev;
	dev_t dev;
	int ret;

	bdev = lookup_bdev(backing_dev_path);
	if (IS_ERR(bdev)) {
		pmfs_info("Backing device not found\n");
		ret = -EINVAL;
		goto fail;
	}

	dev = bdev->bd_dev;
	if (!bdev->bd_inode) {
		pmfs_info("Backing device inode is NULL\n");
		ret = -EINVAL;
		goto fail;
	}

	if (dev) {
		bdev = blkdev_get_by_dev(dev, FMODE_READ |
					FMODE_WRITE | FMODE_EXCL, cinfo);
		if(IS_ERR(bdev)) {
			return -EINVAL;
			goto fail;
		}

		pmfs_info("Opened handle to the block device %p\n", bdev);
		cinfo->bs_bdev = bdev;

		if (bdev->bd_disk){
			cinfo->backing_store_rqueue = bdev_get_queue(bdev);
			pmfs_info("Backing store %p request queue is %p\n",
					bdev, cinfo->backing_store_rqueue);
			if (cinfo->backing_store_rqueue) {
				pmfs_info("max_request_in_queue %lu, "
					"max_sectors %d, "
					"physical_block_size %d, "
					"io_min %d, io_op %d, "
					"make_request_fn %p\n",
				cinfo->backing_store_rqueue->nr_requests,
				cinfo->backing_store_rqueue->limits.max_sectors,
				cinfo->backing_store_rqueue->limits.physical_block_size,
			 	cinfo->backing_store_rqueue->limits.io_min,
				cinfo->backing_store_rqueue->limits.io_opt,
				cinfo->backing_store_rqueue->make_request_fn
				);
				pmfs_info("Backing store number %d\n",
					bdev->bd_dev);

				return 0;

			} else
				pmfs_info("Backing store request queue "
						"is null pointer\n");
		} else
			pmfs_info("Backing store bdisk is null\n");
	}

	ret = -EINVAL;

fail:
	return ret;
}

int pmfs_cache_init(struct pmfs_sb_info *sbi, char* backing_dev_path)
{
	struct pmfs_cache_info *cinfo = kzalloc(sizeof(struct pmfs_cache_info),
						GFP_KERNEL);
	int ret;

	if (!cinfo) {
		pmfs_info("Failed to allocate pmfs cache info struct\n");
		return -ENOMEM;
	}

	pmfs_info("Init PMFS cache, backing device %s\n", backing_dev_path);
	ret = pmfs_cache_init_backing_dev(cinfo, backing_dev_path);

	if (ret != 0) {
		kfree(cinfo);
		return ret;
	}

	pmfs_info("cache enabled\n");
	sbi->cache_info = cinfo;

	return 0;
}

void pmfs_cache_exit(struct pmfs_sb_info *sbi)
{
	struct pmfs_cache_info *cinfo = sbi->cache_info;

	pmfs_info("exiting cache\n");
	if (cinfo->bs_bdev)
		blkdev_put(cinfo->bs_bdev, FMODE_READ |
					FMODE_WRITE | FMODE_EXCL);

	kfree(cinfo);
}
