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
/* pci functions in 2.6 kernels have problems allocating dma buffers,
 * but seem to work fine with dma functions
 */
typedef struct workqueue_struct *workqueue;
#define new_workqueue(queue, name) (queue) = create_workqueue(name)
#include <asm/dma-mapping.h>
#define PCI_DMA_ALLOC_COHERENT(pci_dev,size,dma_handle) \
	dma_alloc_coherent(&pci_dev->dev,size,dma_handle,GFP_KERNEL|__GFP_DMA)
#define PCI_DMA_FREE_COHERENT(pci_dev,size,cpu_addr,dma_handle) \
	dma_free_coherent(&pci_dev->dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(pci_dev,addr,size,direction) \
	dma_map_single(&pci_dev->dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(pci_dev,dma_handle,size,direction) \
	dma_unmap_single(&pci_dev->dev,dma_handle,size,direction)
#else // linux version <= 2.5.41
#define PCI_DMA_ALLOC_COHERENT(dev,size,dma_handle) \
	pci_alloc_consistent(dev,size,dma_handle)
#define PCI_DMA_FREE_COHERENT(dev,size,cpu_addr,dma_handle) \
	pci_free_consistent(dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(dev,addr,size,direction) \
	pci_map_single(dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(dev,dma_handle,size,direction) \
	pci_unmap_single(dev,dma_handle,size,direction)
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
typedef task_queue workqueue;
#define new_workqueue(queue, name) DECLARE_TASK_QUEUE(queue)
#define queue_work(queue, work) do { \
		queue_task(&queue, work); \
		run_task_queue(&queue); \
	} while (0)
#include <linux/smp_lock.h>
#ifdef CONFIG_PREEMPT
#define in_atomic() ((preempt_get_count() & ~PREEMPT_ACTIVE) != kernel_locked())
#else
#define in_atomic() 1
#endif // CONFIG_PREEMPT
#endif // LINUX_VERSION_CODE

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

#define KMALLOC_THRESHOLD 131072

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

/* DEBUG macros */

#define DBGTRACE(fmt, ...) (void)0
#define DBGTRACE1(fmt, ...) (void)0
#define DBGTRACE2(fmt, ...) (void)0
#define DBGTRACE3(fmt, ...) (void)0
#define DBGTRACE4(fmt, ...) (void)0

#define MESSAGE(level, fmt, ...) printk(level "ndiswrapper (%s:%d): " fmt "\n", \
				 __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define WARNING(fmt, ...) MESSAGE(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MESSAGE(KERN_ERR, fmt, ## __VA_ARGS__)
#define INFO(fmt, ...) MESSAGE(KERN_INFO, fmt, ## __VA_ARGS__)

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(fmt, ...) printk(KERN_INFO "%s:%d " fmt "\n", \
				  __FUNCTION__, __LINE__, ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 1
#undef DBGTRACE1
#define DBGTRACE1(fmt, ...) DBGTRACE(fmt, ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 2
#undef DBGTRACE2
#define DBGTRACE2(fmt, ...) DBGTRACE(fmt, ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 3
#undef DBGTRACE3
#define DBGTRACE3(fmt, ...) DBGTRACE(fmt, ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 4
#undef DBGTRACE4
#define DBGTRACE4(fmt, ...) DBGTRACE(fmt, ## __VA_ARGS__)
#endif

#define TRACEENTER(fmt, ...) DBGTRACE("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER1(fmt, ...) DBGTRACE1("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER2(fmt, ...) DBGTRACE2("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER3(fmt, ...) DBGTRACE3("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER4(fmt, ...) DBGTRACE4("Enter " fmt , ## __VA_ARGS__)

#define TRACEEXIT(stmt) do { DBGTRACE("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT1(stmt) do { DBGTRACE1("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT2(stmt) do { DBGTRACE2("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT3(stmt) do { DBGTRACE3("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT4(stmt) do { DBGTRACE4("%s", "Exit"); stmt; } while(0)

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#endif // NDISWRAPPER_H
