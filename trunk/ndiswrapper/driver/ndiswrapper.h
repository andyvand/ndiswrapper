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

#ifndef NDISWRAPPER_H
#define NDISWRAPPER_H

#include <linux/types.h>
#include <linux/timer.h>

#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/pm.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <asm/mman.h>

#include <linux/version.h>

#define DRV_NAME "ndiswrapper"

#define STDCALL __attribute__((__stdcall__, regparm(0)))
#define NOREGPARM __attribute__((regparm(0)))
#define packed __attribute__((packed))
#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))

/* Workqueue / task queue backwards compatibility stuff */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
#else
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
#define HAVE_ETHTOOL 1
#endif

/* Interrupt backwards compatibility stuff */
#include <linux/interrupt.h>
#ifndef IRQ_HANDLED
#define IRQ_HANDLED
#define IRQ_NONE
#define irqreturn_t void
#endif

#ifndef free_netdev
#define free_netdev kfree
#endif


#ifdef DEBUG
#define DBGTRACE(s, args...) printk(s, args)
#else
#define DBGTRACE(s, ...)
#endif

#define VMALLOC_THRESHOLD 65536

#define TICKSPERSEC             10000000
#define SECSPERDAY              86400
 
/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970       ((369 * 365 + 89) * (u64)SECSPERDAY)
#define TICKS_1601_TO_1970      (SECS_1601_TO_1970 * TICKSPERSEC)

#define UNIMPL() do { \
    printk(KERN_ERR "%s --UNIMPLEMENTED--\n", __FUNCTION__ );	\
  } while (0)

typedef void *WRAP_FUNC(void);

struct wrap_func
{
	char *name;
	WRAP_FUNC *func;
};

#define STRFY(S) #S
#define WRAP_FUNC_ENTRY(Func) {STRFY(Func), (WRAP_FUNC *)Func}

struct wrap_alloc
{
	struct list_head list;
	void *ptr;
};

void *wrap_kmalloc(size_t size, int flags);
void wrap_kfree(void *ptr);
void wrap_kfree_all(void);

#endif // NDISWRAPPER_H
