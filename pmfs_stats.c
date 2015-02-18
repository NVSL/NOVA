#include "pmfs.h"

const char *Timingstring[TIMING_NUM] = 
{
	"xip_read",
	"xip_write",
	"xip_write_fast",
	"memcpy_read",
	"memcpy_write",
	"logging",
};

u64 Timingstats[TIMING_NUM];
u64 Countstats[TIMING_NUM];

void pmfs_print_timing_stats(void)
{
	int i;

	printk("======== PMFS kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		if (measure_timing) {
			printk("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			printk("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}
}

void pmfs_clear_stats(void)
{
	int i;

	printk("======== Clear PMFS kernel timing stats ========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
	}
}
