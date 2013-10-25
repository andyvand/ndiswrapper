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
#include "wrapper.h"

#define MAX_PROC_STR_LEN 32

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
static kuid_t proc_kuid;
static kgid_t proc_kgid;
#else
#define proc_kuid proc_uid
#define proc_kgid proc_gid
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
	de->uid = uid;
	de->gid = gid;
}
#endif

#define add_text(p, fmt, ...) (p += sprintf(p, fmt, ##__VA_ARGS__))

static struct proc_dir_entry *wrap_procfs_entry;

static int procfs_read_ndis_stats(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_device *wnd = (struct ndis_device *)data;
	struct ndis_wireless_stats stats;
	NDIS_STATUS res;
	ndis_rssi rssi;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = mp_query(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (!res)
		add_text(p, "signal_level=%d dBm\n", (s32)rssi);

	res = mp_query(wnd, OID_802_11_STATISTICS, &stats, sizeof(stats));
	if (!res) {
		add_text(p, "tx_frames=%llu\n", stats.tx_frag);
		add_text(p, "tx_multicast_frames=%llu\n", stats.tx_multi_frag);
		add_text(p, "tx_failed=%llu\n", stats.failed);
		add_text(p, "tx_retry=%llu\n", stats.retry);
		add_text(p, "tx_multi_retry=%llu\n", stats.multi_retry);
		add_text(p, "tx_rtss_success=%llu\n", stats.rtss_succ);
		add_text(p, "tx_rtss_fail=%llu\n", stats.rtss_fail);
		add_text(p, "ack_fail=%llu\n", stats.ack_fail);
		add_text(p, "frame_duplicates=%llu\n", stats.frame_dup);
		add_text(p, "rx_frames=%llu\n", stats.rx_frag);
		add_text(p, "rx_multicast_frames=%llu\n", stats.rx_multi_frag);
		add_text(p, "fcs_errors=%llu\n", stats.fcs_err);
	}

	if (p - page > count) {
		ERROR("wrote %td bytes (limit is %u)\n",
		      p - page, count);
		*eof = 1;
	}

	return p - page;
}

static int procfs_read_ndis_encr(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_device *wnd = (struct ndis_device *)data;
	int i, encr_status, auth_mode, infra_mode;
	NDIS_STATUS res;
	struct ndis_essid essid;
	mac_address ap_address;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = mp_query(wnd, OID_802_11_BSSID,
		       &ap_address, sizeof(ap_address));
	if (res)
		memset(ap_address, 0, ETH_ALEN);
	add_text(p, "ap_address=%2.2X", ap_address[0]);
	for (i = 1; i < ETH_ALEN; i++)
		add_text(p, ":%2.2X", ap_address[i]);
	add_text(p, "\n");

	res = mp_query(wnd, OID_802_11_SSID, &essid, sizeof(essid));
	if (!res)
		add_text(p, "essid=%.*s\n", essid.length, essid.essid);

	res = mp_query_int(wnd, OID_802_11_ENCRYPTION_STATUS, &encr_status);
	if (!res) {
		typeof(&wnd->encr_info.keys[0]) tx_key;
		add_text(p, "tx_key=%u\n", wnd->encr_info.tx_key_index);
		add_text(p, "key=");
		tx_key = &wnd->encr_info.keys[wnd->encr_info.tx_key_index];
		if (tx_key->length > 0)
			for (i = 0; i < tx_key->length; i++)
				add_text(p, "%2.2X", tx_key->key[i]);
		else
			add_text(p, "off");
		add_text(p, "\n");
		add_text(p, "encr_mode=%d\n", encr_status);
	}
	res = mp_query_int(wnd, OID_802_11_AUTHENTICATION_MODE, &auth_mode);
	if (!res)
		add_text(p, "auth_mode=%d\n", auth_mode);
	res = mp_query_int(wnd, OID_802_11_INFRASTRUCTURE_MODE, &infra_mode);
	add_text(p, "mode=%s\n", (infra_mode == Ndis802_11IBSS) ? "adhoc" :
		 (infra_mode == Ndis802_11Infrastructure) ? "managed" : "auto");
	if (p - page > count) {
		WARNING("wrote %td bytes (limit is %u)",
			p - page, count);
		*eof = 1;
	}

	return p - page;
}

static int procfs_read_ndis_hw(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_device *wnd = (struct ndis_device *)data;
	struct ndis_configuration config;
	enum ndis_power power_mode;
	NDIS_STATUS res;
	ndis_tx_power_level tx_power;
	ULONG bit_rate;
	ndis_rts_threshold rts_threshold;
	ndis_fragmentation_threshold frag_threshold;
	ndis_antenna antenna;
	ULONG packet_filter;
	int n;
	mac_address mac;
	char *hw_status[] = {"ready", "initializing", "resetting", "closing",
			     "not ready"};

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	res = mp_query_int(wnd, OID_GEN_HARDWARE_STATUS, &n);
	if (res == NDIS_STATUS_SUCCESS && n >= 0 && n < ARRAY_SIZE(hw_status))
		add_text(p, "status=%s\n", hw_status[n]);

	res = mp_query(wnd, OID_802_3_CURRENT_ADDRESS, mac, sizeof(mac));
	if (!res)
		add_text(p, "mac: " MACSTRSEP "\n", MAC2STR(mac));
	res = mp_query(wnd, OID_802_11_CONFIGURATION, &config, sizeof(config));
	if (!res) {
		add_text(p, "beacon_period=%u msec\n", config.beacon_period);
		add_text(p, "atim_window=%u msec\n", config.atim_window);
		add_text(p, "frequency=%u kHz\n", config.ds_config);
		add_text(p, "hop_pattern=%u\n", config.fh_config.hop_pattern);
		add_text(p, "hop_set=%u\n", config.fh_config.hop_set);
		add_text(p, "dwell_time=%u msec\n",
			 config.fh_config.dwell_time);
	}

	res = mp_query(wnd, OID_802_11_TX_POWER_LEVEL,
		       &tx_power, sizeof(tx_power));
	if (!res)
		add_text(p, "tx_power=%u mW\n", tx_power);

	res = mp_query(wnd, OID_GEN_LINK_SPEED, &bit_rate, sizeof(bit_rate));
	if (!res)
		add_text(p, "bit_rate=%u kBps\n", (u32)bit_rate / 10);

	res = mp_query(wnd, OID_802_11_RTS_THRESHOLD,
		       &rts_threshold, sizeof(rts_threshold));
	if (!res)
		add_text(p, "rts_threshold=%u bytes\n", rts_threshold);

	res = mp_query(wnd, OID_802_11_FRAGMENTATION_THRESHOLD,
		       &frag_threshold, sizeof(frag_threshold));
	if (!res)
		add_text(p, "frag_threshold=%u bytes\n", frag_threshold);

	res = mp_query_int(wnd, OID_802_11_POWER_MODE, &power_mode);
	if (!res)
		add_text(p, "power_mode=%s\n",
			 (power_mode == NDIS_POWER_OFF) ? "always_on" :
			 (power_mode == NDIS_POWER_MAX) ? "max_savings" :
							  "min_savings");

	res = mp_query(wnd, OID_802_11_NUMBER_OF_ANTENNAS,
		       &antenna, sizeof(antenna));
	if (!res)
		add_text(p, "num_antennas=%u\n", antenna);

	res = mp_query(wnd, OID_802_11_TX_ANTENNA_SELECTED,
		       &antenna, sizeof(antenna));
	if (!res)
		add_text(p, "tx_antenna=%u\n", antenna);

	res = mp_query(wnd, OID_802_11_RX_ANTENNA_SELECTED,
		       &antenna, sizeof(antenna));
	if (!res)
		add_text(p, "rx_antenna=%u\n", antenna);

	add_text(p, "encryption_modes=%s%s%s%s%s%s%s\n",
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

	res = mp_query_int(wnd, OID_GEN_CURRENT_PACKET_FILTER, &packet_filter);
	if (!res) {
		if (packet_filter != wnd->packet_filter)
			WARNING("wrong packet_filter? 0x%08x, 0x%08x\n",
				packet_filter, wnd->packet_filter);
		add_text(p, "packet_filter: 0x%08x\n", packet_filter);
	}
	if (p - page > count) {
		WARNING("wrote %td bytes (limit is %u)",
			p - page, count);
		*eof = 1;
	}

	return p - page;
}

static int procfs_read_ndis_settings(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	char *p = page;
	struct ndis_device *wnd = (struct ndis_device *)data;
	struct wrap_device_setting *setting;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	add_text(p, "hangcheck_interval=%d\n", (hangcheck_interval == 0) ?
		 (wnd->hangcheck_interval / HZ) : -1);

	list_for_each_entry(setting, &wnd->wd->settings, list) {
		add_text(p, "%s=%s\n", setting->name, setting->value);
	}

	list_for_each_entry(setting, &wnd->wd->driver->settings, list) {
		add_text(p, "%s=%s\n", setting->name, setting->value);
	}

	return p - page;
}

static int procfs_write_ndis_settings(struct file *file, const char __user *buf,
				      unsigned long count, void *data)
{
	struct ndis_device *wnd = (struct ndis_device *)data;
	char setting[MAX_PROC_STR_LEN], *p;
	unsigned int i;
	NDIS_STATUS res;

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
		hangcheck_del(wnd);
		if (i > 0) {
			wnd->hangcheck_interval = i * HZ;
			hangcheck_add(wnd);
		}
	} else if (!strcmp(setting, "suspend")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i <= 0 || i > 3)
			return -EINVAL;
		i = -1;
		if (wrap_is_pci_bus(wnd->wd->dev_bus))
			i = wrap_pnp_suspend_pci_device(wnd->wd->pci.pdev,
							PMSG_SUSPEND);
		else if (wrap_is_usb_bus(wnd->wd->dev_bus))
			i = wrap_pnp_suspend_usb_device(wnd->wd->usb.intf,
							PMSG_SUSPEND);
		if (i)
			return -EINVAL;
	} else if (!strcmp(setting, "resume")) {
		i = -1;
		if (wrap_is_pci_bus(wnd->wd->dev_bus))
			i = wrap_pnp_resume_pci_device(wnd->wd->pci.pdev);
		else if (wrap_is_usb_bus(wnd->wd->dev_bus))
			i = wrap_pnp_resume_usb_device(wnd->wd->usb.intf);
		if (i)
			return -EINVAL;
	} else if (!strcmp(setting, "stats_enabled")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		if (i > 0)
			wnd->iw_stats_enabled = TRUE;
		else
			wnd->iw_stats_enabled = FALSE;
	} else if (!strcmp(setting, "packet_filter")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		res = mp_set_int(wnd, OID_GEN_CURRENT_PACKET_FILTER, i);
		if (res)
			WARNING("setting packet_filter failed: %08X", res);
	} else if (!strcmp(setting, "reinit")) {
		if (ndis_reinit(wnd) != NDIS_STATUS_SUCCESS)
			return -EFAULT;
	} else {
		struct ndis_configuration_parameter param;
		struct unicode_string key;
		struct ansi_string ansi;

		if (!p)
			return -EINVAL;
		p++;
		RtlInitAnsiString(&ansi, p);
		if (RtlAnsiStringToUnicodeString(&param.data.string, &ansi,
						 TRUE) != STATUS_SUCCESS)
			EXIT1(return -EFAULT);
		param.type = NdisParameterString;
		RtlInitAnsiString(&ansi, setting);
		if (RtlAnsiStringToUnicodeString(&key, &ansi,
						 TRUE) != STATUS_SUCCESS) {
			RtlFreeUnicodeString(&param.data.string);
			EXIT1(return -EINVAL);
		}
		NdisWriteConfiguration(&res, wnd->nmb, &key, &param);
		RtlFreeUnicodeString(&key);
		RtlFreeUnicodeString(&param.data.string);
		if (res != NDIS_STATUS_SUCCESS)
			return -EFAULT;
	}
	return count;
}

int wrap_procfs_add_ndis_device(struct ndis_device *wnd)
{
	struct proc_dir_entry *procfs_entry;

	if (wrap_procfs_entry == NULL)
		return -ENOMEM;

	if (wnd->procfs_iface) {
		ERROR("%s already registered?", wnd->net_dev->name);
		return -EINVAL;
	}
	wnd->procfs_iface = proc_mkdir(wnd->net_dev->name, wrap_procfs_entry);
	if (wnd->procfs_iface == NULL) {
		ERROR("couldn't create proc directory");
		return -ENOMEM;
	}
	proc_set_user(wnd->procfs_iface, proc_kuid, proc_kgid);

	procfs_entry = create_proc_entry("hw", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'hw'");
		goto err_hw;
	}
	proc_set_user(procfs_entry, proc_kuid, proc_kgid);
	procfs_entry->data = wnd;
	procfs_entry->read_proc = procfs_read_ndis_hw;

	procfs_entry = create_proc_entry("stats", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'stats'");
		goto err_stats;
	}
	proc_set_user(procfs_entry, proc_kuid, proc_kgid);
	procfs_entry->data = wnd;
	procfs_entry->read_proc = procfs_read_ndis_stats;

	procfs_entry = create_proc_entry("encr", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'encr'");
		goto err_encr;
	}
	proc_set_user(procfs_entry, proc_kuid, proc_kgid);
	procfs_entry->data = wnd;
	procfs_entry->read_proc = procfs_read_ndis_encr;

	procfs_entry = create_proc_entry("settings", S_IFREG |
					 S_IRUSR | S_IRGRP |
					 S_IWUSR | S_IWGRP, wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'settings'");
		goto err_settings;
	}
	proc_set_user(procfs_entry, proc_kuid, proc_kgid);
	procfs_entry->data = wnd;
	procfs_entry->read_proc = procfs_read_ndis_settings;
	procfs_entry->write_proc = procfs_write_ndis_settings;

	return 0;

err_settings:
	remove_proc_entry("encr", wnd->procfs_iface);
err_encr:
	remove_proc_entry("stats", wnd->procfs_iface);
err_stats:
	remove_proc_entry("hw", wnd->procfs_iface);
err_hw:
	remove_proc_entry(wnd->procfs_iface->name, wrap_procfs_entry);
	wnd->procfs_iface = NULL;
	return -ENOMEM;
}

void wrap_procfs_remove_ndis_device(struct ndis_device *wnd)
{
	struct proc_dir_entry *procfs_iface = xchg(&wnd->procfs_iface, NULL);

	if (procfs_iface == NULL)
		return;
	remove_proc_entry("hw", procfs_iface);
	remove_proc_entry("stats", procfs_iface);
	remove_proc_entry("encr", procfs_iface);
	remove_proc_entry("settings", procfs_iface);
	if (wrap_procfs_entry)
		remove_proc_entry(procfs_iface->name, wrap_procfs_entry);
}

static int procfs_read_debug(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	char *p = page;
#if ALLOC_DEBUG
	enum alloc_type type;
#endif

	if (off != 0) {
		*eof = 1;
		return 0;
	}
	add_text(p, "%d\n", debug);
#if ALLOC_DEBUG
	for (type = 0; type < ALLOC_TYPE_MAX; type++)
		add_text(p, "total size of allocations in %s: %d\n",
			 alloc_type_name[type], alloc_size(type));
#endif
	return p - page;
}

static int procfs_write_debug(struct file *file, const char __user *buf,
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	struct user_namespace *ns = current_user_ns();
	proc_kuid = make_kuid(ns, proc_uid);
	if (!uid_valid(proc_kuid)) {
		ERROR("invalid UID\n");
		return -EINVAL;
	}
	proc_kgid = make_kgid(ns, proc_gid);
	if (!gid_valid(proc_kgid)) {
		ERROR("invalid GID\n");
		return -EINVAL;
	}
#endif

	wrap_procfs_entry = proc_mkdir(DRIVER_NAME, proc_net_root);
	if (wrap_procfs_entry == NULL) {
		ERROR("couldn't create procfs directory");
		return -ENOMEM;
	}
	proc_set_user(wrap_procfs_entry, proc_kuid, proc_kgid);

	procfs_entry = create_proc_entry("debug", S_IFREG | S_IRUSR | S_IRGRP,
					 wrap_procfs_entry);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'debug'");
		return -ENOMEM;
	}
	proc_set_user(procfs_entry, proc_kuid, proc_kgid);
	procfs_entry->read_proc = procfs_read_debug;
	procfs_entry->write_proc = procfs_write_debug;

	return 0;
}

void wrap_procfs_remove(void)
{
	if (wrap_procfs_entry == NULL)
		return;
	remove_proc_entry("debug", wrap_procfs_entry);
	remove_proc_entry(DRIVER_NAME, proc_net_root);
}
