/*
 *  Copyright (C) 2006-2007 Giridhar Pemmasani
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

	res = mp_query(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (!res)
		p += sprintf(p, "signal_level=%d dBm\n", (s32)rssi);

	res = mp_query(wnd, OID_802_11_STATISTICS, &stats, sizeof(stats));
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

	if (off != 0) {
		*eof = 1;
		return 0;
	}

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
	int i;
	NDIS_STATUS status;
	char buf[100];
	struct ndis_dot11_current_operation_mode *op_mode;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

	i = 0;
	status = mp_query_int(wnd, OID_DOT11_CURRENT_PHY_ID, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "phy_id=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_NIC_POWER_STATE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "nic_power=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_HARDWARE_PHY_STATE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "phy_power=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_POWER_MGMT_REQUEST, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "power_mgmt=%d\n", i);
	op_mode = (void *)buf;
	status = mp_query(wnd, OID_DOT11_CURRENT_OPERATION_MODE,
			  op_mode, sizeof(*op_mode));
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "op_mode=0x%x\n", op_mode->mode);
	status = mp_query_int(wnd, OID_DOT11_RF_USAGE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "rf_usage=%d\n", i);
	status = mp_query_int(wnd, OID_DOT11_AUTO_CONFIG_ENABLED, &i);
	if (status == NDIS_STATUS_SUCCESS)
		p += sprintf(p, "auto_config=0x%x\n", i);

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
		     hangcheck_interval == 0 ?
		     (int)(wnd->hangcheck_interval / HZ) : -1);

	list_for_each_entry(setting, &wnd->wd->settings, list) {
		p += sprintf(p, "%s=%s\n", setting->name, setting->value);
	}

	list_for_each_entry(setting, &wnd->wd->driver->settings, list) {
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
		if (wrap_is_pci_bus(wnd->wd->dev_bus))
			i = wrap_pnp_suspend_pci_device(wnd->wd->pci.pdev,
							PMSG_SUSPEND);
		else
#ifdef CONFIG_USB
			i = wrap_pnp_suspend_usb_device(wnd->wd->usb.intf,
							PMSG_SUSPEND);
#else
		i = -1;
#endif
		if (i)
			return -EINVAL;
	} else if (!strcmp(setting, "resume")) {
		if (wrap_is_pci_bus(wnd->wd->dev_bus))
			i = wrap_pnp_resume_pci_device(wnd->wd->pci.pdev);
		else
#ifdef CONFIG_USB
			i = wrap_pnp_resume_usb_device(wnd->wd->usb.intf);
#else
		i = -1;
#endif
		if (i)
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
	} else if (!strcmp(setting, "packet_filter")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		res = mp_set_int(wnd, OID_GEN_CURRENT_PACKET_FILTER, i);
		if (res)
			WARNING("setting packet_filter failed: %08X", res);
	} else if (!strcmp(setting, "nic_power")) {
		BOOLEAN b;
		if (!p)
			return -EINVAL;
		p++;
		if (simple_strtol(p, NULL, 10))
			b = TRUE;
		else
			b = FALSE;
		res = mp_set_info(wnd, OID_DOT11_NIC_POWER_STATE, &b,
				  sizeof(b), NULL, NULL);
		if (res)
			WARNING("setting nic_power failed: %08X", res);
	} else if (!strcmp(setting, "phy_power")) {
		BOOLEAN b;
		if (!p)
			return -EINVAL;
		p++;
		if (simple_strtol(p, NULL, 10))
			b = TRUE;
		else
			b = FALSE;
		res = mp_set_info(wnd, OID_DOT11_HARDWARE_PHY_STATE, &b,
				  sizeof(b), NULL, NULL);
		if (res)
			WARNING("setting phy_power failed: %08X", res);
	} else if (!strcmp(setting, "phy_id")) {
		if (!p)
			return -EINVAL;
		p++;
		i = simple_strtol(p, NULL, 10);
		res = mp_set_int(wnd, OID_DOT11_CURRENT_PHY_ID, i);
		if (res)
			WARNING("setting phy_id to %d failed: %08X", i, res);
	}
	return count;
}

int wrap_procfs_add_ndis_device(struct wrap_ndis_device *wnd)
{
	struct proc_dir_entry *procfs_entry;

	ENTER1("%p", wnd);
	if (wrap_procfs_entry == NULL)
		return -ENOMEM;

	if (wnd->procfs_iface) {
		ERROR("%s already registered?", wnd->netdev_name);
		return -EINVAL;
	}
	wnd->procfs_iface = proc_mkdir(wnd->netdev_name, wrap_procfs_entry);
	if (wnd->procfs_iface == NULL) {
		ERROR("couldn't create proc directory");
		return -ENOMEM;
	}
	wnd->procfs_iface->uid = proc_uid;
	wnd->procfs_iface->gid = proc_gid;

	procfs_entry = create_proc_entry("hw", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'hw'");
		goto err_hw;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_hw;
	}

	procfs_entry = create_proc_entry("stats", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'stats'");
		goto err_stats;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_stats;
	}

	procfs_entry = create_proc_entry("encr", S_IFREG | S_IRUSR | S_IRGRP,
					 wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'encr'");
		goto err_encr;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_encr;
	}

	procfs_entry = create_proc_entry("settings", S_IFREG |
					 S_IRUSR | S_IRGRP |
					 S_IWUSR | S_IWGRP, wnd->procfs_iface);
	if (procfs_entry == NULL) {
		ERROR("couldn't create proc entry for 'settings'");
		goto err_settings;
	} else {
		procfs_entry->uid = proc_uid;
		procfs_entry->gid = proc_gid;
		procfs_entry->data = wnd;
		procfs_entry->read_proc = procfs_read_ndis_settings;
		procfs_entry->write_proc = procfs_write_ndis_settings;
	}
	EXIT1(return 0);

err_settings:
	remove_proc_entry("encr", wnd->procfs_iface);
err_encr:
	remove_proc_entry("stats", wnd->procfs_iface);
err_stats:
	remove_proc_entry("hw", wnd->procfs_iface);
err_hw:
	remove_proc_entry(wnd->netdev_name, wrap_procfs_entry);
	wnd->procfs_iface = NULL;
	return -ENOMEM;
}

void wrap_procfs_remove_ndis_device(struct wrap_ndis_device *wnd)
{
	struct proc_dir_entry *procfs_iface = xchg(&wnd->procfs_iface, NULL);

	if (procfs_iface == NULL)
		return;
	remove_proc_entry("hw", procfs_iface);
	remove_proc_entry("stats", procfs_iface);
	remove_proc_entry("encr", procfs_iface);
	remove_proc_entry("settings", procfs_iface);
	if (wrap_procfs_entry)
		remove_proc_entry(wnd->netdev_name, wrap_procfs_entry);
}

static int procfs_read_debug(char *page, char **start, off_t off,
			     int count, int *eof, void *data)
{
	char *p = page;
	enum alloc_type type;

	if (off != 0) {
		*eof = 1;
		return 0;
	}
	p += sprintf(p, "%d\n", debug);
	type = 0;
#ifdef ALLOC_DEBUG
	for (type = 0; type < ALLOC_TYPE_MAX; type++)
		p += sprintf(p, "total size of allocations in %d: %d\n",
			     type, alloc_size(type));
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

	wrap_procfs_entry = proc_mkdir(DRIVER_NAME, proc_net_root);
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
	remove_proc_entry(DRIVER_NAME, proc_net_root);
}
