/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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
#include <asm/uaccess.h>

#include "ndis.h"
#include "iw_ndis.h"
#include "wrapndis.h"
#include "pnp.h"

#define MAX_PROC_STR_LEN 32

static struct proc_dir_entry *wrap_procfs_entry;
extern int proc_uid, proc_gid, hangcheck_interval;

static int procfs_read_ndis_stats(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	char *p = page;
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	struct ndis_wireless_stats stats;
	NDIS_STATUS res;
	ndis_rssi rssi;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = miniport_query_info(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (!res)
		p += sprintf(p, "signal_level=%d dBm\n", (s32)rssi);

	res = miniport_query_info(wnd, OID_802_11_STATISTICS,
				  &stats, sizeof(stats));
	if (!res) {

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

	if (p - page > count) {
		ERROR("wrote %lu bytes (limit is %u)\n",
		      (unsigned long)(p - page), count);
		*eof = 1;
	}

	return (p - page);
}

static int procfs_read_ndis_encr(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	char *p = page;
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	int i, encr_status, auth_mode, infra_mode;
	NDIS_STATUS res;
	struct ndis_essid essid;
	mac_address ap_address;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = miniport_query_info(wnd, OID_802_11_BSSID,
				  &ap_address, sizeof(ap_address));
	if (res)
		memset(ap_address, 0, ETH_ALEN);
	p += sprintf(p, "ap_address=%2.2X", ap_address[0]);
	for (i = 1 ; i < ETH_ALEN ; i++)
		p += sprintf(p, ":%2.2X", ap_address[i]);
	p += sprintf(p, "\n");

	res = miniport_query_info(wnd, OID_802_11_SSID, &essid,
				  sizeof(essid));
	if (!res) {
		essid.essid[essid.length] = '\0';
		p += sprintf(p, "essid=%s\n", essid.essid);
	}
	res = miniport_query_int(wnd, OID_802_11_ENCRYPTION_STATUS,
				 &encr_status);
	if (!res) {
		typeof(&wnd->encr_info.keys[0]) tx_key;
		p += sprintf(p, "tx_key=%u\n", wnd->encr_info.tx_key_index);
		p += sprintf(p, "key=");
		tx_key = &wnd->encr_info.keys[wnd->encr_info.tx_key_index];
		if (tx_key->length > 0)
			for (i = 0; i < tx_key->length; i++)
				p += sprintf(p, "%2.2X", tx_key->key[i]);
		else
			p += sprintf(p, "off");
		p += sprintf(p, "\n");
		p += sprintf(p, "encr_mode=%d\n", encr_status);
	}
	res = miniport_query_int(wnd, OID_802_11_AUTHENTICATION_MODE,
				  &auth_mode);
	if (!res)
		p += sprintf(p, "auth_mode=%d\n", auth_mode);
	res = miniport_query_int(wnd, OID_802_11_INFRASTRUCTURE_MODE,
				 &infra_mode);
	p += sprintf(p, "mode=%s\n", (infra_mode == Ndis802_11IBSS) ?
		     "adhoc" : (infra_mode == Ndis802_11Infrastructure) ?
		     "managed" : "auto");
	if (p - page > count) {
		WARNING("wrote %lu bytes (limit is %u)",
			(unsigned long)(p - page), count);
		*eof = 1;
	}

	return (p - page);
}

static int procfs_read_ndis_hw(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	char *p = page;
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	struct ndis_configuration config;
	unsigned int power_mode;
	NDIS_STATUS res;
	ndis_tx_power_level tx_power;
	ULONG bit_rate;
	ndis_rts_threshold rts_threshold;
	ndis_fragmentation_threshold frag_threshold;
	ndis_antenna antenna;
	ULONG packet_filter;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = miniport_query_info(wnd, OID_802_11_CONFIGURATION,
				  &config, sizeof(config));
	if (!res) {
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

	res = miniport_query_info(wnd, OID_802_11_TX_POWER_LEVEL,
				  &tx_power, sizeof(tx_power));
	if (!res)
		p += sprintf(p, "tx_power=%u mW\n", tx_power);

	res = miniport_query_info(wnd, OID_GEN_LINK_SPEED,
				  &bit_rate, sizeof(bit_rate));
	if (!res)
		p += sprintf(p, "bit_rate=%u kBps\n", (u32)bit_rate / 10);

	res = miniport_query_info(wnd, OID_802_11_RTS_THRESHOLD,
				  &rts_threshold, sizeof(rts_threshold));
	if (!res)
		p += sprintf(p, "rts_threshold=%u bytes\n", rts_threshold);

	res = miniport_query_info(wnd, OID_802_11_FRAGMENTATION_THRESHOLD,
				  &frag_threshold, sizeof(frag_threshold));
	if (!res)
		p += sprintf(p, "frag_threshold=%u bytes\n", frag_threshold);

	res = miniport_query_int(wnd, OID_802_11_POWER_MODE, &power_mode);
	if (!res)
		p += sprintf(p, "power_mode=%s\n",
			     (power_mode == NDIS_POWER_OFF) ?
			     "always_on" :
			     (power_mode == NDIS_POWER_MAX) ?
			     "max_savings" : "min_savings");

	res = miniport_query_info(wnd, OID_802_11_NUMBER_OF_ANTENNAS,
				  &antenna, sizeof(antenna));
	if (!res)
		p += sprintf(p, "num_antennas=%u\n", antenna);

	res = miniport_query_info(wnd, OID_802_11_TX_ANTENNA_SELECTED,
				  &antenna, sizeof(antenna));
	if (!res)
		p += sprintf(p, "tx_antenna=%u\n", antenna);

	res = miniport_query_info(wnd, OID_802_11_RX_ANTENNA_SELECTED,
				  &antenna, sizeof(antenna));
	if (!res)
		p += sprintf(p, "rx_antenna=%u\n", antenna);

	p += sprintf(p, "encryption_modes=%s%s%s%s%s%s%s\n",
		     test_bit(Ndis802_11Encryption1Enabled, &wnd->capa.encr) ?
		     "WEP" : "none",

		     test_bit(Ndis802_11Encryption2Enabled, &wnd->capa.encr) ?
		     "; TKIP with WPA" : "",
		     test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
		     ", WPA2" : "",
		     test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
		     ", WPA2PSK" : "",

		     test_bit(Ndis802_11Encryption3Enabled, &wnd->capa.encr) ?
		     "; AES/CCMP with WPA" : "",
		     test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
		     ", WPA2" : "",
		     test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
		     ", WPA2PSK" : "");

	res = miniport_query_int(wnd, OID_GEN_CURRENT_PACKET_FILTER,
				 &packet_filter);
	if (!res) {
		if (packet_filter != wnd->packet_filter)
			WARNING("wrong packet_filter? 0x%08x, 0x%08x\n",
				packet_filter, wnd->packet_filter);
		p += sprintf(p, "packet_filter: 0x%08x\n", packet_filter);
	}
	if (p - page > count) {
		WARNING("wrote %lu bytes (limit is %u)",
			(unsigned long)(p - page), count);
		*eof = 1;
	}

	return (p - page);
}

static int procfs_read_ndis_settings(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	char *p = page;
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	struct wrap_device_setting *setting;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	p += sprintf(p, "hangcheck_interval=%d\n",
		     hangcheck_interval > 0 ?
		     (int)(wnd->hangcheck_interval / HZ) : -1);

	list_for_each_entry(setting, &wnd->wd->settings, list) {
		p += sprintf(p, "%s=%s\n", setting->name, setting->value);
	}

	return (p - page);
}

static int procfs_write_ndis_settings(struct file *file, const char *buf,
				      unsigned long count, void *data)
{
	struct wrap_ndis_device *wnd = (struct wrap_ndis_device *)data;
	char setting[MAX_PROC_STR_LEN], *p;
	unsigned int i;
	NTSTATUS res;

	if (count > MAX_PROC_STR_LEN)
		return -EINVAL;

	memset(setting, 0, sizeof(setting));
	if (copy_from_user(setting, buf, count))
		return -EFAULT;

	if ((p = strchr(setting, '\n')))
		*p = 0;

	if ((p = strchr(setting, '=')))
		*p = 0;

	if (!strcmp(setting, "hangcheck_interval")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		hangcheck_interval = i;
		hangcheck_del(wnd);
		hangcheck_add(wnd);
	} else if (!strcmp(setting, "get_encryption_capa")) {
		get_encryption_capa(wnd);
		printk(KERN_INFO
		       "%s: encryption modes supported: %s%s%s%s%s%s%s\n",
		       wnd->net_dev->name,
		       test_bit(Ndis802_11Encryption1Enabled,
				&wnd->capa.encr) ?
		       "WEP" : "none",

		       test_bit(Ndis802_11Encryption2Enabled,
				&wnd->capa.encr) ?
		       "; TKIP with WPA" : "",
		       test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
		       ", WPA2" : "",
		       test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
		       ", WPA2PSK" : "",

		       test_bit(Ndis802_11Encryption3Enabled,
				&wnd->capa.encr) ?
		       "; AES/CCMP with WPA" : "",
		       test_bit(Ndis802_11AuthModeWPA2, &wnd->capa.auth) ?
		       ", WPA2" : "",
		       test_bit(Ndis802_11AuthModeWPA2PSK, &wnd->capa.auth) ?
		       ", WPA2PSK" : "");
	} else if (!strcmp(setting, "suspend")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i <= 0 || i > 3)
			return -EINVAL;
		if (wrap_is_pci_bus(wnd->wd->dev_bus_type))
			i = wrap_pnp_suspend_pci_device(wnd->wd->pci.pdev,
							PMSG_SUSPEND);
		else
#if defined(CONFIG_USB) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			i = wrap_pnp_suspend_usb_device(wnd->wd->usb.intf,
							PMSG_SUSPEND);
#else
		i = -1;
#endif
		if (i)
			return -EINVAL;
	} else if (!strcmp(setting, "resume")) {
		if (wrap_is_pci_bus(wnd->wd->dev_bus_type))
			i = wrap_pnp_resume_pci_device(wnd->wd->pci.pdev);
		else
#if defined(CONFIG_USB) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			i = wrap_pnp_resume_usb_device(wnd->wd->usb.intf);
#else
		i = -1;
#endif
		if (i)
			return -EINVAL;
	} else if (!strcmp(setting, "reinit")) {
		if (ndis_reinit(wnd))
			return -EINVAL;
#ifdef USB_DEBUG
	} else if (!strcmp(setting, "irp")) {
		struct irp *irp;
		struct io_stack_location *irp_sl;
		int major_fn, minor_fn, n;
		struct device_object *dev;
		if (!p)
			return -EINVAL;
		p++;
		n = sscanf(p, "%d,%d,%x", &major_fn, &minor_fn, (int *)&dev);
		DBGTRACE1("n = %d, mj = %d, mn = %d, dev = %p", n, major_fn,
			  minor_fn, dev);
		if (n != 3)
			return -EINVAL;
		irp = IoAllocateIrp(dev->stack_count, FALSE);
		DBGTRACE1("count: %d, irp = %p", dev->stack_count, irp);
		DBGTRACE1("drv_obj: %p", dev->drv_obj);
		irp_sl = IoGetNextIrpStackLocation(irp);
		irp_sl->major_fn = major_fn;
		irp_sl->minor_fn = minor_fn;
		irp->io_status.status = STATUS_NOT_SUPPORTED;
		res = 0;
		res = IoCallDriver(dev, irp);
		DBGTRACE1("status = %d", res);
#endif
	} else if (!strcmp(setting, "power_profile")) {
		struct miniport_char *miniport;
		ULONG profile_inf;

		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i < 0 || i > 1)
			return -EINVAL;

		miniport = &wnd->wd->driver->ndis_driver->miniport;
		if (!miniport->pnp_event_notify)
			return -EFAULT;

		/* 1 for AC and 0 for Battery */
		if (i)
			profile_inf = NdisPowerProfileAcOnLine;
		else
			profile_inf = NdisPowerProfileBattery;

		miniport->pnp_event_notify(wnd->nmb->adapter_ctx,
					   NdisDevicePnPEventPowerProfileChanged,
					   &profile_inf, sizeof(profile_inf));
	} else if (!strcmp(setting, "auth_mode")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i <= 0 || i > 5)
			return -EINVAL;

		if (set_auth_mode(wnd, i))
			return -EINVAL;
	} else if (!strcmp(setting, "encr_mode")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i <= 0 || i > 7)
			return -EINVAL;

		if (set_encr_mode(wnd, i))
			return -EINVAL;
	} else if (!strcmp(setting, "stats_enabled")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i > 0)
			wnd->stats_enabled = TRUE;
		else
			wnd->stats_enabled = FALSE;
	} else if (!strcmp(setting, "tx_antenna")) {
		ndis_antenna antenna;

		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 16);
		res = miniport_query_info(wnd, OID_802_11_NUMBER_OF_ANTENNAS,
					  &antenna, sizeof(antenna));
		if (res)
			return -EINVAL;
		if (i >= -1 && i < antenna)
			antenna = i;
		res = miniport_set_info(wnd, OID_802_11_TX_ANTENNA_SELECTED,
				  &antenna, sizeof(antenna));
		if (res)
			return -EINVAL;
	} else if (!strcmp(setting, "rx_antenna")) {
		ndis_antenna antenna;

		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 16);
		res = miniport_query_info(wnd, OID_802_11_NUMBER_OF_ANTENNAS,
					  &antenna, sizeof(antenna));
		if (res)
			return -EINVAL;
		if (i >= -1 && i < antenna)
			antenna = i;
		res = miniport_set_info(wnd, OID_802_11_RX_ANTENNA_SELECTED,
				  &antenna, sizeof(antenna));
		if (res)
			return -EINVAL;
	} else if (!strcmp(setting, "reset")) {
		res = miniport_reset(wnd);
		DBGTRACE2("%08X", res);
	} else if (!strcmp(setting, "packet_filter")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		res = miniport_set_int(wnd, OID_GEN_CURRENT_PACKET_FILTER, i);
		if (res)
			WARNING("setting packet_filter failed: %08X", res);
	}
	return count;
}

int wrap_procfs_add_ndis_device(struct wrap_ndis_device *wnd)
{
	struct net_device *dev = wnd->net_dev;
	struct proc_dir_entry *proc_iface, *procfs_entry;

	wnd->procfs_iface = NULL;
	if (wrap_procfs_entry == NULL)
		return -ENOMEM;

	proc_iface = proc_mkdir(dev->name, wrap_procfs_entry);

	wnd->procfs_iface = proc_iface;

	if (proc_iface == NULL) {
		ERROR("couldn't create proc directory");
		return -ENOMEM;
	}
	proc_iface->uid = proc_uid;
	proc_iface->gid = proc_gid;

	procfs_entry = create_proc_entry("hw", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'hw'");
		return -ENOMEM;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_hw;
	}

	procfs_entry = create_proc_entry("stats", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'stats'");
		return -ENOMEM;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_stats;
	}

	procfs_entry = create_proc_entry("encr", S_IFREG | S_IRUSR | S_IRGRP,
					 proc_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'encr'");
		return -ENOMEM;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_encr;
	}

	procfs_entry = create_proc_entry("settings", S_IFREG |
					 S_IRUSR | S_IRGRP |
					 S_IWUSR | S_IWGRP, proc_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'settings'");
		return -ENOMEM;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_settings;
		procfs_entry->write_proc = procfs_write_ndis_settings;
	}
	return 0;
}

void wrap_procfs_remove_ndis_device(struct wrap_ndis_device *wnd)
{
	struct net_device *dev = wnd->net_dev;
	struct proc_dir_entry *procfs_iface = wnd->procfs_iface;

	if (procfs_iface == NULL)
		return;
	remove_proc_entry("hw", procfs_iface);
	remove_proc_entry("stats", procfs_iface);
	remove_proc_entry("encr", procfs_iface);
	remove_proc_entry("settings", procfs_iface);
	if (wrap_procfs_entry != NULL)
		remove_proc_entry(dev->name, wrap_procfs_entry);
	wnd->procfs_iface = NULL;
}

static int procfs_read_debug(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	char *p = page;

	if (off != 0) {
		*eof = 1;
		return 0;
	}
	p += sprintf(p, "%d\n", debug);
#ifdef ALLOC_INFO
	do {
		enum alloc_type type;

		for (type = 0; type < ALLOC_TYPE_MAX; type++)
			p += sprintf(p, "allocation size in %d: %d\n",
				     type, alloc_size(type));
	} while (0)
#endif
	return (p - page);
}

static int procfs_write_debug(struct file *file, const char *buf,
			      unsigned long count, void *data)
{
	int i;
	char setting[MAX_PROC_STR_LEN], *p;

	if (count > MAX_PROC_STR_LEN)
		return -EINVAL;

	memset(setting, 0, sizeof(setting));
	if (copy_from_user(setting, buf, count))
		return -EFAULT;

	if ((p = strchr(setting, '\n')))
		*p = 0;

	if ((p = strchr(setting, '=')))
		*p = 0;

	i = simple_strtol(setting, NULL, 10);
	if (i >= 0 && i < 10)
		debug = i;
	else
		return -EINVAL;
	return count;
}

int wrap_procfs_init(void)
{
	struct proc_dir_entry *procfs_entry;

	wrap_procfs_entry = proc_mkdir(DRIVER_NAME, proc_net);
	if (wrap_procfs_entry == NULL) {
		ERROR("couldn't create procfs directory");
		return -ENOMEM;
	}
	wrap_procfs_entry->uid = proc_uid;
	wrap_procfs_entry->gid = proc_gid;

	procfs_entry = create_proc_entry("debug", S_IFREG | S_IRUSR | S_IRGRP,
					 wrap_procfs_entry);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'debug'");
		return -ENOMEM;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->read_proc  = procfs_read_debug;
		procfs_entry->write_proc = procfs_write_debug;
	}
	return 0;
}

void wrap_procfs_remove(void)
{
	if (wrap_procfs_entry == NULL)
		return;
	remove_proc_entry("debug", wrap_procfs_entry);
	remove_proc_entry(DRIVER_NAME, proc_net);
}
