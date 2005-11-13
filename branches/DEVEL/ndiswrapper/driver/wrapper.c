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

#include <linux/module.h>
#include <linux/kmod.h>

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
struct workqueue_struct *ndiswrapper_wq;

WRAP_MODULE_PARM_STRING(if_name, 0400);
MODULE_PARM_DESC(if_name, "Network interface name or template "
		 "(default: wlan%d)");
WRAP_MODULE_PARM_INT(proc_uid, 0600);
MODULE_PARM_DESC(proc_uid, "The uid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(proc_gid, 0600);
MODULE_PARM_DESC(proc_gid, "The gid of the files created in /proc "
		 "(default: 0).");
WRAP_MODULE_PARM_INT(hangcheck_interval, 0600);
/* 0 - default value provided by NDIS driver,
 * positive value - force hangcheck interval to that many seconds
 * negative value - disable hangcheck
 */
WRAP_MODULE_PARM_INT(debug, 0600);
MODULE_PARM_DESC(debug, "debug level");

MODULE_PARM_DESC(hangcheck_interval, "The interval, in seconds, for checking"
		 " if driver is hung. (default: 0)");

MODULE_AUTHOR("ndiswrapper team <ndiswrapper-general@lists.sourceforge.net>");
#ifdef MODULE_VERSION
MODULE_VERSION(DRIVER_VERSION);
#endif

extern KSPIN_LOCK timer_lock;

static void hangcheck_proc(unsigned long data)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)data;

	TRACEENTER3("");
	if (wd->hangcheck_interval <= 0)
		return;

	set_bit(HANGCHECK, &wd->wrapper_work);
	schedule_work(&wd->wrapper_worker);

	wd->hangcheck_timer.expires += wd->hangcheck_interval;
	add_timer(&wd->hangcheck_timer);

	TRACEEXIT3(return);
}

void hangcheck_add(struct wrapper_dev *wd)
{
	if (!wd->driver->miniport.hangcheck || wd->hangcheck_interval <= 0)
		return;
	init_timer(&wd->hangcheck_timer);
	wd->hangcheck_timer.data = (unsigned long)wd;
	wd->hangcheck_timer.function = &hangcheck_proc;
	wd->hangcheck_timer.expires = jiffies + wd->hangcheck_interval;
	add_timer(&wd->hangcheck_timer);
	return;
}

void hangcheck_del(struct wrapper_dev *wd)
{
	del_timer_sync(&wd->hangcheck_timer);
}

#ifdef USE_OWN_WORKQUEUE
/* we need to get thread for the task running ndiswrapper_wq, so
 * schedule a worker for it soon after initializing ndiswrapper_wq */

static struct work_struct _ndiswrapper_wq_init;
static int _ndiswrapper_wq_init_state;
#define NDISWRAPPER_WQ_INIT 1
#define NDISWRAPPER_WQ_EXIT 2

static void _ndiswrapper_wq_init_worker(void *data)
{
	struct task_struct *task;
	struct nt_thread *thread;

	task = get_current();
	if (_ndiswrapper_wq_init_state == NDISWRAPPER_WQ_INIT) {
		thread = wrap_create_thread(task);
		DBGTRACE1("task: %p, pid: %d, thread: %p",
			  task, task->pid, thread);
		if (!thread) {
			_ndiswrapper_wq_init_state = -1;
			return;
		}
	} else {
		thread = KeGetCurrentThread();
		if (thread) {
			DBGTRACE1("task: %p, pid: %d, thread: %p",
				  task, task->pid, thread);
			wrap_remove_thread(thread);
		}
	}
	_ndiswrapper_wq_init_state = 0;
}
#endif

static void module_cleanup(void)
{
	loader_exit();
#ifdef CONFIG_USB
	usb_exit();
#endif
#ifdef USE_OWN_WORKQUEUE
	_ndiswrapper_wq_init_state = NDISWRAPPER_WQ_EXIT;
	schedule_work(&_ndiswrapper_wq_init);
	while (_ndiswrapper_wq_init_state) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(4);
	}
	destroy_workqueue(ndiswrapper_wq);
#endif
	ndiswrapper_procfs_remove();
	ndis_exit();
	ntoskernel_exit();
	misc_funcs_exit();
}

static int __init wrapper_init(void)
{
	char *argv[] = {"loadndisdriver", 
#if defined(DEBUG) && DEBUG >= 1
			"1"
#else
			"0"
#endif
			, UTILS_VERSION, "-a", 0};
	char *env[] = {NULL};
	int ret;

//	debug = 2;
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

	if (misc_funcs_init() || ntoskernel_init() || ndis_init()
#ifdef CONFIG_USB
	     || usb_init()
#endif
		)
		goto err;
#ifdef USE_OWN_WORKQUEUE
	ndiswrapper_wq = create_singlethread_workqueue("ndiswrapwq");
	INIT_WORK(&_ndiswrapper_wq_init, _ndiswrapper_wq_init_worker, 0);
	_ndiswrapper_wq_init_state = NDISWRAPPER_WQ_INIT;
	schedule_work(&_ndiswrapper_wq_init);
	while (_ndiswrapper_wq_init_state > 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(4);
	}
	if (_ndiswrapper_wq_init_state < 0)
		goto err;
#endif
	ndiswrapper_procfs_init();
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

MODULE_LICENSE("GPL");
