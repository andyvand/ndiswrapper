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

#include "ndis.h"
#include "iw_ndis.h"
#include "loader.h"
#include "pnp.h"

char *if_name = "wlan%d";
int proc_uid, proc_gid;
int hangcheck_interval;

#if defined(DEBUG) && (DEBUG > 0)
int debug = DEBUG;
#else
int debug = 0;
#endif

/* use own workqueue instead of shared one, to avoid depriving
 * others */
struct workqueue_struct *wrap_wq;

WRAP_MODULE_PARM_STRING(if_name, 0400);
MODULE_PARM_DESC(if_name, "Network interface name or template "
		 "(default: wlan%d)");
WRAP_MODULE_PARM_INT(proc_uid, 0600);
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(proc_gid, 0600);
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(debug, 0600);
MODULE_PARM_DESC(debug, "debug level");

/* 0 - default value provided by NDIS driver,
 * positive value - force hangcheck interval to that many seconds
 * negative value - disable hangcheck
 */
WRAP_MODULE_PARM_INT(hangcheck_interval, 0600);
MODULE_PARM_DESC(hangcheck_interval, "The interval, in seconds, for checking"
		 " if driver is hung. (default: 0)");

MODULE_AUTHOR("ndiswrapper team <ndiswrapper-general@lists.sourceforge.net>");
#ifdef MODULE_DESCRIPTION
MODULE_DESCRIPTION("NDIS wrapper driver");
#endif
#ifdef MODULE_VERSION
MODULE_VERSION(DRIVER_VERSION);
#endif
MODULE_LICENSE("GPL");

static void module_cleanup(void)
{
	loader_exit();
#ifdef CONFIG_USB
	usb_exit();
#endif

#ifdef USE_OWN_WORKQUEUE
	if (wrap_wq)
		destroy_workqueue(wrap_wq);
#endif
	wrap_procfs_remove();
	ndis_exit();
	ntoskernel_exit();
	misc_funcs_exit();
	wrapmem_exit();
}

static int __init wrapper_init(void)
{
	char *argv[] = {"loadndisdriver", WRAP_CMD_LOAD_DEVICES,
#if defined(DEBUG) && DEBUG >= 1
			"1"
#else
			"0"
#endif
			, UTILS_VERSION, NULL};
	char *env[] = {NULL};
	int ret;

	wrapmem_init();
	printk(KERN_INFO "%s version %s loaded (preempt=%s,smp=%s)\n",
	       DRIVER_NAME, DRIVER_VERSION,
#if defined CONFIG_PREEMPT
	       "yes",
#else
	       "no",
#endif
#ifdef CONFIG_SMP
	       "yes"
#else
	       "no"
#endif
		);

#ifdef USE_OWN_WORKQUEUE
	wrap_wq = create_singlethread_workqueue("wrap_wq");
#endif
	if (misc_funcs_init() || ntoskernel_init() || ndis_init()
#ifdef CONFIG_USB
	    || usb_init()
#endif
		)
		goto err;
	wrap_procfs_init();
	if (loader_init())
		goto err;
	DBGTRACE1("calling loadndisdriver");
	ret = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
				  , 1
#endif
		);
	if (ret) {
		ERROR("loadndiswrapper failed (%d); check system log "
		      "for messages from 'loadndisdriver'", ret);
		goto err;
	}
	TRACEEXIT1(return 0);

err:
	module_cleanup();
	ERROR("%s: initialization failed", DRIVER_NAME);
	return -EINVAL;
}

static void __exit wrapper_exit(void)
{
	TRACEENTER1("");
	module_cleanup();
}

module_init(wrapper_init);
module_exit(wrapper_exit);

