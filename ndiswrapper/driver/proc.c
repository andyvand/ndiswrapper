#include <linux/proc_fs.h>
#include <linux/module.h>

#include "ndis.h"

static struct proc_dir_entry *ndis_proc_entry, *ndis_proc_entry_stats,
	*ndis_proc_entry_wep;
static int proc_uid, proc_gid, proc_perm = 0440;

MODULE_PARM(proc_uid, "i");
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc (default: 0).");
MODULE_PARM(proc_gid, "i");
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc. (default: 0).");
MODULE_PARM(proc_perm, "i");
MODULE_PARM_DESC(proc_perm, "The permission bits of files created in /proc (default: 440).");


static int ndis_proc_read_stats(char *page, char **start, off_t off,
				       int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *) data;
	struct ndis_wireless_stats *stats = &handle->ndis_stats;

	if (off != 0) {
		*eof = 1;
		return 0;
	}
	p += sprintf(p, "signal_level=%ld\n", handle->rssi);

	p += sprintf(p, "tx_frames=%Lu\n", stats->tx_frag);
	p += sprintf(p, "tx_multicast_frames=%Lu\n", stats->tx_multi_frag);
	p += sprintf(p, "tx_failed=%Lu\n", stats->failed);
	p += sprintf(p, "tx_retry=%Lu\n", stats->retry);
	p += sprintf(p, "tx_multi_rerty=%Lu\n", stats->multi_retry);
	p += sprintf(p, "tx_rtss_success=%Lu\n", stats->rtss_succ);
	p += sprintf(p, "tx_rtss_fail=%Lu\n", stats->rtss_fail);
	p += sprintf(p, "ack_fail=%Lu\n", stats->ack_fail);
	p += sprintf(p, "frame_duplicates=%Lu\n", stats->frame_dup);
	p += sprintf(p, "rx_frames=%Lu\n", stats->rx_frag);
	p += sprintf(p, "rx_multicast_frames=%Lu\n", stats->rx_multi_frag);
	p += sprintf(p, "fcs_errors=%Lu\n", stats->fcs_err);

	if (p - page > count)
	{
		printk(KERN_ERR "%s: %s wrote %u bytes (limit is %u)\n",
		       handle->net_dev->name, __FUNCTION__, p - page, count);
		*eof = 1;
	}

	return (p - page);
}

static int ndis_proc_read_wep(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *) data;
	int i;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	p += sprintf(p, "key_index=%u\n",
		     (__u32)handle->wep.keyindex & 0x7fff);
	p += sprintf(p, "key=");

	if (handle->wep.keylength > 0)
		for (i = 0 ; i < NDIS_ENCODING_TOKEN_MAX &&
			     i < handle->wep.keylength; i++)
			p += sprintf(p, "%02x", handle->wep.keymaterial[i]);
	else
		p += sprintf(p, "off");
	p += sprintf(p, "\n");

	p += sprintf(p, "status=%s\n",
		     (handle->wep_status == NDIS_ENCODE_ENABLED) ?
		     "enabled" : "disabled");
	p += sprintf(p, "auth_mode=%s\n",
		     (handle->auth_mode == NDIS_ENCODE_RESTRICTED) ?
		     "restricted" : "open");
	if (p - page > count)
	{
		printk(KERN_ERR "%s: %s wrote %u bytes (limit is %u)\n",
		       handle->net_dev->name, __FUNCTION__, p - page, count);
		*eof = 1;
	}

	return (p - page);
}

int ndis_init_proc(struct ndis_handle *handle)
{
	struct net_device *dev = handle->net_dev;
	
	/* TODO: should we create at /proc, or at /proc/net? */
	ndis_proc_entry = create_proc_entry(dev->name, S_IFDIR, NULL);
	if (ndis_proc_entry == NULL)
	{
		printk(KERN_INFO "%s: Couldn't create proc directory %s\n",
		       dev->name, dev->name);
		return -1;
	}
	ndis_proc_entry->uid = proc_uid;
	ndis_proc_entry->gid = proc_gid;

	ndis_proc_entry_stats = create_proc_entry("stats", S_IFREG | (S_IRUGO & proc_perm), ndis_proc_entry);
	if (ndis_proc_entry_stats == NULL)
		printk(KERN_INFO "%s: Couldn't create proc entry for 'stats'\n", dev->name);
	else
	{
		ndis_proc_entry_stats->uid = proc_uid;
		ndis_proc_entry_stats->gid = proc_gid;
		ndis_proc_entry_stats->data = handle;
		ndis_proc_entry_stats->read_proc = ndis_proc_read_stats;
	}

	ndis_proc_entry_wep = create_proc_entry("wep", S_IFREG | (S_IRUGO & proc_perm), ndis_proc_entry);
	if (ndis_proc_entry_wep == NULL)
		printk(KERN_INFO "%s: Couldn't create proc entry for 'wep'\n",
		       dev->name);
	else
	{
		ndis_proc_entry_wep->uid = proc_uid;
		ndis_proc_entry_wep->gid = proc_gid;
		ndis_proc_entry_wep->data = handle;
		ndis_proc_entry_wep->read_proc = ndis_proc_read_wep;
//		ndis_proc_entry_wep->write_proc = ndis_proc_write_wep;
	}
	
	return 0;
}


void ndis_remove_proc(struct ndis_handle *handle)
{
	struct net_device *dev = handle->net_dev;

	remove_proc_entry("stats", ndis_proc_entry);
	remove_proc_entry("wep", ndis_proc_entry);
	remove_proc_entry(dev->name, NULL);
}
