#include <linux/proc_fs.h>
#include <linux/module.h>

#include "ndis.h"

static struct proc_dir_entry *ndiswrapper_proc_entry, *ndis_proc_entry,
	*ndis_proc_entry_stats, *ndis_proc_entry_wep, *ndis_proc_entry_hw;
extern int proc_uid, proc_gid;

static int ndis_proc_read_stats(char *page, char **start, off_t off,
				       int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *) data;
	struct ndis_wireless_stats stats;
	unsigned int res, written, needed;
	long rssi;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = doquery(handle, NDIS_OID_RSSI, (char*)&rssi,
		      sizeof(rssi), &written, &needed);
	if (!res)
		p += sprintf(p, "signal_level=%ld dBm\n", rssi);

	res = doquery(handle, NDIS_OID_STATISTICS, (char*)&stats,
		      sizeof(stats), &written, &needed);
	if (!res)
	{
		
		p += sprintf(p, "tx_frames=%Lu\n", stats.tx_frag);
		p += sprintf(p, "tx_multicast_frames=%Lu\n",
			     stats.tx_multi_frag);
		p += sprintf(p, "tx_failed=%Lu\n", stats.failed);
		p += sprintf(p, "tx_retry=%Lu\n", stats.retry);
		p += sprintf(p, "tx_multi_rerty=%Lu\n", stats.multi_retry);
		p += sprintf(p, "tx_rtss_success=%Lu\n", stats.rtss_succ);
		p += sprintf(p, "tx_rtss_fail=%Lu\n", stats.rtss_fail);
		p += sprintf(p, "ack_fail=%Lu\n", stats.ack_fail);
		p += sprintf(p, "frame_duplicates=%Lu\n", stats.frame_dup);
		p += sprintf(p, "rx_frames=%Lu\n", stats.rx_frag);
		p += sprintf(p, "rx_multicast_frames=%Lu\n",
			     stats.rx_multi_frag);
		p += sprintf(p, "fcs_errors=%Lu\n", stats.fcs_err);
	}

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
	int i, wep_status, auth_mode, op_mode;
	unsigned int res, written, needed;
	struct essid_req essid;
	__u8 ap_address[ETH_ALEN];

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = doquery(handle, NDIS_OID_BSSID, (char*)&ap_address,
		      sizeof(ap_address), &written, &needed);
	if (res)
		memset(ap_address, 255, ETH_ALEN);
	p += sprintf(p, "ap_address=");
	for (i = 0 ; i < ETH_ALEN ; i++)
		p += sprintf(p, "%02x:", ap_address[i]);
	p += sprintf(p, "%02x", ap_address[i]);
	p += sprintf(p, "\n");

	res = doquery(handle, NDIS_OID_ESSID, (char*)&essid,
		      sizeof(essid), &written, &needed);
	if (!res)
	{
		essid.essid[essid.len] = '\0';
		p += sprintf(p, "essid=%s\n", essid.essid);
	}

	res = query_int(handle, NDIS_OID_WEP_STATUS, &wep_status);
	res |= query_int(handle, NDIS_OID_AUTH_MODE, &auth_mode);

	if (!res)
	{
		p += sprintf(p, "key_index=%u\n",
			     (__u32)handle->wep.keyindex & 0x7fff);
		p += sprintf(p, "key=");
		if (handle->wep.keylength > 0)
			for (i = 0 ; i < NDIS_ENCODING_TOKEN_MAX &&
				     i < handle->wep.keylength; i++)
				p += sprintf(p, "%02x",
					     handle->wep.keymaterial[i]);
		else
			p += sprintf(p, "off");
		p += sprintf(p, "\n");
		
		p += sprintf(p, "status=%sabled\n",
			     (wep_status == NDIS_ENCODE_ENABLED) ?
			     "en" : "dis");
		p += sprintf(p, "auth_mode=%s\n",
			     (auth_mode == NDIS_ENCODE_RESTRICTED) ?
			     "restricted" : "open");
	}

	res = query_int(handle, NDIS_OID_MODE, &op_mode);
	p += sprintf(p, "mode=%s\n",
		     (op_mode == NDIS_MODE_ADHOC) ?
		     "adhoc" : 
		     (op_mode == NDIS_MODE_INFRA) ?
		     "managed" : "auto");
	if (p - page > count)
	{
		printk(KERN_ERR "%s: %s wrote %u bytes (limit is %u)\n",
		       handle->net_dev->name, __FUNCTION__, p - page, count);
		*eof = 1;
	}

	return (p - page);
}

static int ndis_proc_read_hw(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *)data;
	struct ndis_configuration config;
	unsigned int res, written, needed, power_mode;
	unsigned long tx_power, bit_rate, rts_threshold, frag_threshold;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = doquery(handle, NDIS_OID_CONFIGURATION,
		      (char*)&config, sizeof(config), &written, &needed);
	if (!res)
	{
		p += sprintf(p, "beacon_period=%u msec\n",
			     config.beacon_period);
		p += sprintf(p, "atim_window=%u msec\n", config.atim_window);
		p += sprintf(p, "frequency=%u kHZ\n", config.ds_config);
		p += sprintf(p, "hop_pattern=%u\n",
			     config.fh_config.hop_pattern);
		p += sprintf(p, "hop_set=%u\n",
			     config.fh_config.hop_set);
		p += sprintf(p, "dwell_time=%u msec\n",
			     config.fh_config.dwell_time);
	}

	res = doquery(handle, NDIS_OID_TX_POWER_LEVEL, (char*)&tx_power,
		      sizeof(tx_power), &written, &needed);
	if (!res)
		p += sprintf(p, "tx_power=%lu mW\n", tx_power);

	res = doquery(handle, NDIS_OID_GEN_SPEED, (char*)&bit_rate,
		      sizeof(bit_rate), &written, &needed);
	if (!res)
		p += sprintf(p, "bit_rate=%lu kBps\n", bit_rate / 10);

	res = doquery(handle, NDIS_OID_RTS_THRESH, (char*)&rts_threshold,
		      sizeof(rts_threshold), &written, &needed);
	if (!res)
		p += sprintf(p, "rts_threshold=%lu bytes\n", rts_threshold);

	res = doquery(handle, NDIS_OID_FRAG_THRESH, (char*)&frag_threshold,
		      sizeof(frag_threshold), &written, &needed);
	if (!res)
		p += sprintf(p, "frag_threshold=%lu bytes\n", frag_threshold);

	res = query_int(handle, NDIS_OID_POWER_MODE, &power_mode);
	if (!res)
		p += sprintf(p, "power_mode=%s\n",
			     (power_mode == NDIS_POWER_OFF) ?
			     "always_on" :
			     (power_mode == NDIS_POWER_MAX) ?
			     "max_savings" : "min_savings");

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
	
	ndiswrapper_proc_entry = create_proc_entry("ndiswrapper",
						   S_IFDIR, proc_net);
	if (ndiswrapper_proc_entry == NULL)
	{
		printk(KERN_INFO "%s: Couldn't create proc directory %s\n",
		       dev->name, dev->name);
		return -1;
	}
	ndiswrapper_proc_entry->uid = proc_uid;
	ndiswrapper_proc_entry->gid = proc_gid;

	ndis_proc_entry = create_proc_entry(dev->name,
					    S_IFDIR, ndiswrapper_proc_entry);
	if (ndis_proc_entry == NULL)
	{
		printk(KERN_INFO "%s: Couldn't create proc directory %s\n",
		       dev->name, dev->name);
		return -1;
	}
	ndis_proc_entry->uid = proc_uid;
	ndis_proc_entry->gid = proc_gid;

	ndis_proc_entry_stats = create_proc_entry("stats",
						  S_IFREG | S_IRUSR | S_IRGRP,
						  ndis_proc_entry);
	if (ndis_proc_entry_stats == NULL)
		printk(KERN_INFO "%s: Couldn't create proc entry for 'stats'\n", dev->name);
	else
	{
		ndis_proc_entry_stats->uid = proc_uid;
		ndis_proc_entry_stats->gid = proc_gid;
		ndis_proc_entry_stats->data = handle;
		ndis_proc_entry_stats->read_proc = ndis_proc_read_stats;
	}

	ndis_proc_entry_wep = create_proc_entry("wep",
						S_IFREG | S_IRUSR | S_IRGRP,
						ndis_proc_entry);
	if (ndis_proc_entry_wep == NULL)
		printk(KERN_INFO "%s: Couldn't create proc entry for 'wep'\n",
		       dev->name);
	else
	{
		ndis_proc_entry_wep->uid = proc_uid;
		ndis_proc_entry_wep->gid = proc_gid;
		ndis_proc_entry_wep->data = handle;
		ndis_proc_entry_wep->read_proc = ndis_proc_read_wep;
	}
	
	ndis_proc_entry_hw = create_proc_entry("hw",
					       S_IFREG | S_IRUSR | S_IRGRP,
					       ndis_proc_entry);
	if (ndis_proc_entry_hw == NULL)
		printk(KERN_INFO "%s: Couldn't create proc entry for 'wep'\n",
		       dev->name);
	else
	{
		ndis_proc_entry_hw->uid = proc_uid;
		ndis_proc_entry_hw->gid = proc_gid;
		ndis_proc_entry_hw->data = handle;
		ndis_proc_entry_hw->read_proc = ndis_proc_read_hw;
	}

	return 0;
}


void ndis_remove_proc(struct ndis_handle *handle)
{
	struct net_device *dev = handle->net_dev;

	remove_proc_entry("stats", ndis_proc_entry);
	remove_proc_entry("wep", ndis_proc_entry);
	remove_proc_entry("hw", ndis_proc_entry);
	remove_proc_entry(dev->name, ndiswrapper_proc_entry);
	remove_proc_entry("ndiswrapper", proc_net);
}
