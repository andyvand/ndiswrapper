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
static void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid)
{
	de->uid = uid;
	de->gid = gid;
}

static void proc_remove(struct proc_dir_entry *de)
{
	if (de)
		remove_proc_entry(de->name, de->parent);
}

#define READ_RET int
#define READ_ARGS \
	char *page, char **start, off_t off, int count, int *eof, void *data
#define READ_PRIV (struct ndis_device *)data
#define WRITE_RET int
#define WRITE_ARGS \
	struct file *file, const char __user *buf, unsigned long count, void *data
#define WRITE_PRIV (struct ndis_device *)data

typedef READ_RET (*proc_read_fn)(READ_ARGS);
typedef WRITE_RET (*proc_write_fn)(WRITE_ARGS);

static int do_proc_make_entry(const char *name, umode_t mode,
			     struct proc_dir_entry *parent,
			     proc_read_fn rfunc, proc_write_fn wfunc,
			     kuid_t uid, kgid_t gid, struct ndis_device *wnd)
{
	struct proc_dir_entry *de;

	de = create_proc_entry(name, mode, parent);
	if (de == NULL) {
		ERROR("couldn't create proc entry for '%s'", name);
		return -ENOMEM;
	}
	de->uid = uid;
	de->gid = gid;
	de->read_proc = rfunc;
	de->write_proc = wfunc;
	de->data = wnd;
	return 0;

#define proc_make_entry_ro(name, parent, wnd) \
	do_proc_make_entry(#name, S_IFREG | S_IRUSR | S_IRGRP, parent, \
			   proc_##name##_read, NULL, proc_kuid, proc_kgid, wnd)
#define proc_make_entry_rw(name, parent, wnd) \
	do_proc_make_entry(#name, \
			   S_IFREG | S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP, \
			   parent, proc_##name##_read, proc_##name##_write, \
			   proc_kuid, proc_kgid, wnd)
}

#define offset_check() \
	if (off != 0) { \
		*eof = 1; \
		return 0; \
	}

#define add_text(fmt, ...) \
	(len += scnprintf(page + len, count - len, fmt, ##__VA_ARGS__))
#endif

static struct proc_dir_entry *wrap_procfs_entry;

static READ_RET proc_stats_read(READ_ARGS)
{
	int len = 0;
	struct ndis_device *wnd = READ_PRIV;
	struct ndis_wireless_stats stats;
	NDIS_STATUS res;
	ndis_rssi rssi;

	offset_check();

	res = mp_query(wnd, OID_802_11_RSSI, &rssi, sizeof(rssi));
	if (!res)
		add_text("signal_level=%d dBm\n", (s32)rssi);

	res = mp_query(wnd, OID_802_11_STATISTICS, &stats, sizeof(stats));
	if (!res) {
		add_text("tx_frames=%llu\n", stats.tx_frag);
		add_text("tx_multicast_frames=%llu\n", stats.tx_multi_frag);
		add_text("tx_failed=%llu\n", stats.failed);
		add_text("tx_retry=%llu\n", stats.retry);
		add_text("tx_multi_retry=%llu\n", stats.multi_retry);
		add_text("tx_rtss_success=%llu\n", stats.rtss_succ);
		add_text("tx_rtss_fail=%llu\n", stats.rtss_fail);
		add_text("ack_fail=%llu\n", stats.ack_fail);
		add_text("frame_duplicates=%llu\n", stats.frame_dup);
		add_text("rx_frames=%llu\n", stats.rx_frag);
		add_text("rx_multicast_frames=%llu\n", stats.rx_multi_frag);
		add_text("fcs_errors=%llu\n", stats.fcs_err);
	}

	return len;
}

static READ_RET proc_encr_read(READ_ARGS)
{
	int len = 0;

	offset_check();

	return len;
}

static READ_RET proc_hw_read(READ_ARGS)
{
	int len = 0;
	struct ndis_device *wnd = READ_PRIV;
	int i;
	NDIS_STATUS status;
	char buf[100];
	struct ndis_dot11_current_operation_mode *op_mode;

	offset_check();

	i = 0;
	status = mp_query_int(wnd, OID_DOT11_CURRENT_PHY_ID, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("phy_id=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_NIC_POWER_STATE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("nic_power=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_HARDWARE_PHY_STATE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("phy_power=%d\n", i);
	i = 0;
	status = mp_query_int(wnd, OID_DOT11_POWER_MGMT_REQUEST, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("power_mgmt=%d\n", i);
	op_mode = (void *)buf;
	status = mp_query(wnd, OID_DOT11_CURRENT_OPERATION_MODE,
			  op_mode, sizeof(*op_mode));
	if (status == NDIS_STATUS_SUCCESS)
		add_text("op_mode=0x%x\n", op_mode->mode);
	status = mp_query_int(wnd, OID_DOT11_RF_USAGE, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("rf_usage=%d\n", i);
	status = mp_query_int(wnd, OID_DOT11_AUTO_CONFIG_ENABLED, &i);
	if (status == NDIS_STATUS_SUCCESS)
		add_text("auto_config=0x%x\n", i);

	return len;
}

static READ_RET proc_settings_read(READ_ARGS)
{
	int len = 0;
	struct ndis_device *wnd = READ_PRIV;
	struct wrap_device_setting *setting;

	offset_check();

	add_text("hangcheck_interval=%d\n", (hangcheck_interval == 0) ?
		 (wnd->hangcheck_interval / HZ) : -1);

	list_for_each_entry(setting, &wnd->wd->settings, list) {
		add_text("%s=%s\n", setting->name, setting->value);
	}

	list_for_each_entry(setting, &wnd->wd->driver->settings, list) {
		add_text("%s=%s\n", setting->name, setting->value);
	}

	return len;
}

static WRITE_RET proc_settings_write(WRITE_ARGS)
{
	struct ndis_device *wnd = WRITE_PRIV;
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

int wrap_procfs_add_ndis_device(struct ndis_device *wnd)
{
	int ret;

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

	ret = proc_make_entry_ro(hw, wnd->procfs_iface, wnd);
	if (ret)
		goto err_hw;

	ret = proc_make_entry_ro(stats, wnd->procfs_iface, wnd);
	if (ret)
		goto err_stats;

	ret = proc_make_entry_ro(encr, wnd->procfs_iface, wnd);
	if (ret)
		goto err_encr;

	ret = proc_make_entry_rw(settings, wnd->procfs_iface, wnd);
	if (ret)
		goto err_settings;

	return 0;

err_settings:
	remove_proc_entry("encr", wnd->procfs_iface);
err_encr:
	remove_proc_entry("stats", wnd->procfs_iface);
err_stats:
	remove_proc_entry("hw", wnd->procfs_iface);
err_hw:
	proc_remove(wnd->procfs_iface);
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
		proc_remove(procfs_iface);
}

static READ_RET proc_debug_read(READ_ARGS)
{
	int len = 0;
#if ALLOC_DEBUG
	enum alloc_type type;
#endif

	offset_check();

	add_text("%d\n", debug);
#if ALLOC_DEBUG
	for (type = 0; type < ALLOC_TYPE_MAX; type++)
		add_text("total size of allocations in %s: %d\n",
			 alloc_type_name[type], alloc_size(type));
#endif
	return len;
}

static WRITE_RET proc_debug_write(WRITE_ARGS)
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
	int ret;

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

	ret = proc_make_entry_rw(debug, wrap_procfs_entry, NULL);

	return ret;
}

void wrap_procfs_remove(void)
{
	if (wrap_procfs_entry == NULL)
		return;
	remove_proc_entry("debug", wrap_procfs_entry);
	proc_remove(wrap_procfs_entry);
}
