/*
 *  Copyright (C) 2003-2004 Pontus Fuchs, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */
#include <linux/proc_fs.h>
#include <linux/module.h>

#include "ndis.h"

static struct proc_dir_entry *ndiswrapper_procfs_entry;
extern int proc_uid, proc_gid;

static int procfs_read_stats(char *page, char **start, off_t off,
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
		ERROR("wrote %u bytes (limit is %u)\n", p - page, count);
		*eof = 1;
	}

	return (p - page);
}

static int procfs_read_wep(char *page, char **start, off_t off,
			   int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *) data;
	int i, wep_status, auth_mode, op_mode;
	unsigned int res, written, needed;
	struct ndis_essid essid;
	mac_address ap_address;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = doquery(handle, NDIS_OID_BSSID, (char*)&ap_address,
		      sizeof(ap_address), &written, &needed);
	if (res)
		memset(ap_address, 0, ETH_ALEN);
	p += sprintf(p, "ap_address=%2.2X", ap_address[0]);
	for (i = 1 ; i < ETH_ALEN ; i++)
		p += sprintf(p, ":%2.2X", ap_address[i]);
	p += sprintf(p, "\n");

	res = doquery(handle, NDIS_OID_ESSID, (char*)&essid,
		      sizeof(essid), &written, &needed);
	if (!res)
	{
		essid.essid[essid.length] = '\0';
		p += sprintf(p, "essid=%s\n", essid.essid);
	}

	res = query_int(handle, NDIS_OID_WEP_STATUS, &wep_status);
	res |= query_int(handle, NDIS_OID_AUTH_MODE, &auth_mode);

	if (!res)
	{
		int active = handle->wep_info.active;
		p += sprintf(p, "tx_key=%u\n", handle->wep_info.active);
		p += sprintf(p, "key=");
		if (handle->wep_info.keys[active].length > 0)
			for (i = 0; i < NDIS_ENCODING_TOKEN_MAX &&
				     i < handle->wep_info.keys[active].length;
			     i++)
				p += sprintf(p, "%2.2X",
					     handle->wep_info.keys[active].key[i]);
		else
			p += sprintf(p, "off");
		p += sprintf(p, "\n");
		
		p += sprintf(p, "status=%sabled\n",
			     (wep_status == WEP_ENABLED) ? "en" : "dis");
		p += sprintf(p, "auth_mode=%s\n",
			     (auth_mode == AUTHMODE_RESTRICTED) ?
			     "restricted" : "open");
	}

	res = query_int(handle, NDIS_OID_MODE, &op_mode);
	p += sprintf(p, "mode=%s\n", (op_mode == NDIS_MODE_ADHOC) ?
		     "adhoc" : (op_mode == NDIS_MODE_INFRA) ?
		     "managed" : "auto");
	if (p - page > count)
	{
		WARNING("wrote %u bytes (limit is %u)", p - page, count);
		*eof = 1;
	}

	return (p - page);
}

static int procfs_read_hw(char *page, char **start, off_t off,
			  int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_handle *handle = (struct ndis_handle *)data;
	struct ndis_configuration config;
	unsigned int res, written, needed, power_mode;
	unsigned long tx_power, bit_rate, rts_threshold, frag_threshold;
	unsigned long antenna;

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

	res = doquery(handle, NDIS_OID_NUM_ANTENNA, (char *)&antenna,
		      sizeof(antenna), &written, &needed);
	if (!res)
		p += sprintf(p, "num_antennas=%lu\n",
			     antenna);

	res = doquery(handle, NDIS_OID_TX_ANTENNA, (char *)&antenna,
		      sizeof(antenna), &written, &needed);
	if (!res)
		p += sprintf(p, "tx_antenna=%lu\n",
			     antenna);

	res = doquery(handle, NDIS_OID_RX_ANTENNA, (char *)&antenna,
		      sizeof(antenna), &written, &needed);
	if (!res)
		p += sprintf(p, "rx_antenna=%lu\n",
			     antenna);

	if (p - page > count)
	{
		WARNING("wrote %u bytes (limit is %u)", p - page, count);
		*eof = 1;
	}

	return (p - page);
}

int ndiswrapper_procfs_init(void)
{
	ndiswrapper_procfs_entry = proc_mkdir(DRV_NAME, proc_net);
	if (ndiswrapper_procfs_entry == NULL)
	{
		ERROR("%s", "Couldn't create procfs directory");
		return -ENOMEM;
	}
	ndiswrapper_procfs_entry->uid = proc_uid;
	ndiswrapper_procfs_entry->gid = proc_gid;
	return 0;
}

int ndiswrapper_procfs_add_iface(struct ndis_handle *handle)
{
	struct net_device *dev = handle->net_dev;
	struct proc_dir_entry *proc_iface, *procfs_entry;

	handle->procfs_iface = NULL;
	if (ndiswrapper_procfs_entry == NULL)
		return -ENOMEM;

	proc_iface = proc_mkdir(dev->name, ndiswrapper_procfs_entry);

	handle->procfs_iface = proc_iface;

	if (proc_iface == NULL)
	{
		ERROR("%s", "Couldn't create proc directory");
		return -ENOMEM;
	}
	proc_iface->uid = proc_uid;
	proc_iface->gid = proc_gid;

	procfs_entry = create_proc_entry("hw", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL)
	{
		ERROR("%s", "Couldn't create proc entry for 'hw'");
		return -ENOMEM;
	}
	else
	{
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = handle;
		procfs_entry->read_proc = procfs_read_hw;
	}

	procfs_entry = create_proc_entry("stats", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL)
	{
		ERROR("%s", "Couldn't create proc entry for 'stats'");
		return -ENOMEM;
	}
	else
	{
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = handle;
		procfs_entry->read_proc = procfs_read_stats;
	}

	procfs_entry = create_proc_entry("wep", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL)
	{
		ERROR("%s", "Couldn't create proc entry for 'wep'");
		return -ENOMEM;
	}
	else
	{
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = handle;
		procfs_entry->read_proc = procfs_read_wep;
	}

	return 0;

}

void ndiswrapper_procfs_remove_iface(struct ndis_handle *handle)
{
	struct net_device *dev = handle->net_dev;
	struct proc_dir_entry *procfs_iface = handle->procfs_iface;

	if (procfs_iface == NULL)
		return;
	remove_proc_entry("hw", procfs_iface);
	remove_proc_entry("stats", procfs_iface);
	remove_proc_entry("wep", procfs_iface);
	if (ndiswrapper_procfs_entry != NULL)
		remove_proc_entry(dev->name, ndiswrapper_procfs_entry);
	handle->procfs_iface = NULL;
}

void ndiswrapper_procfs_remove(void)
{
	if (ndiswrapper_procfs_entry == NULL)
		return;
	remove_proc_entry(DRV_NAME, proc_net);
}
