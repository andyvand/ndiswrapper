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
#include <linux/usb.h>
#include <asm/mman.h>
#include <asm/atomic.h>

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
#include <linux/smp_lock.h>

/* RedHat kernels #define irqs_disabled this way */
#ifndef irqs_disabled
#define irqs_disabled()                \
({                                     \
       unsigned long flags;            \
       __save_flags(flags);            \
       !(flags & (1<<9));              \
})
#endif

#ifdef CONFIG_PREEMPT
#define in_atomic() ((preempt_get_count() & ~PREEMPT_ACTIVE) != kernel_locked())
#else
#define in_atomic() (in_interrupt())
#endif // CONFIG_PREEMPT

#define __GFP_NOWARN 0

#endif // LINUX_VERSION_CODE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
#define HAVE_ETHTOOL 1
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
#undef __wait_event_interruptible_timeout
#undef wait_event_interruptible_timeout
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#define preempt_enable()
#define preempt_disable()
#endif // LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)

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
#define DBGTRACE5(fmt, ...) (void)0

/* for a block of code */
#define DBG_BLOCK() while (0)

#define MSG(level, fmt, ...) printk(level "ndiswrapper (%s:%d): " fmt "\n", \
				    __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define WARNING(fmt, ...) MSG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MSG(KERN_ERR, fmt, ## __VA_ARGS__)
#define INFO(fmt, ...) MSG(KERN_INFO, fmt, ## __VA_ARGS__)

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(fmt, ...) printk(KERN_INFO "ndiswrapper (%s:%d): " fmt "\n", \
				  __FUNCTION__, __LINE__, ## __VA_ARGS__)
#undef DBG_BLOCK
#define DBG_BLOCK()
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

#if defined DEBUG && DEBUG >= 5
#undef DBGTRACE5
#define DBGTRACE5(fmt, ...) DBGTRACE(fmt, ## __VA_ARGS__)
#endif

#define TRACEENTER(fmt, ...) DBGTRACE("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER1(fmt, ...) DBGTRACE1("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER2(fmt, ...) DBGTRACE2("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER3(fmt, ...) DBGTRACE3("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER4(fmt, ...) DBGTRACE4("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER5(fmt, ...) DBGTRACE5("Enter " fmt , ## __VA_ARGS__)

#define TRACEEXIT(stmt) do { DBGTRACE("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT1(stmt) do { DBGTRACE1("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT2(stmt) do { DBGTRACE2("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT3(stmt) do { DBGTRACE3("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT4(stmt) do { DBGTRACE4("%s", "Exit"); stmt; } while(0)
#define TRACEEXIT5(stmt) do { DBGTRACE5("%s", "Exit"); stmt; } while(0)

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define NDIS_SPIN_LOCK_MAGIC 137

struct packed wrap_spinlock
{
	spinlock_t spinlock;
	unsigned short magic;
	unsigned short in_bh;
	atomic_t in_use;
};

static inline void wrap_spin_lock_init(struct wrap_spinlock *lock)
{
	TRACEENTER5("lock: %p", lock);
	spin_lock_init(&lock->spinlock);
	lock->magic = NDIS_SPIN_LOCK_MAGIC;
	atomic_set(&lock->in_use, 0);
	TRACEEXIT5(return);
}
#if defined DEBUG
#define ASSERT(expr) \
if(!(expr)) { \
	ERROR("Assertion failed! %s\n", (#expr)); \
}
#else
#define ASSERT(expr)
#endif

static inline void wrap_spin_lock(struct wrap_spinlock *lock)
{
	TRACEENTER5("lock: %p", lock);
	if (lock->magic != NDIS_SPIN_LOCK_MAGIC)
		WARNING("lock %p is not initlialized (%d)", lock, lock->magic);
	if (atomic_read(&lock->in_use) == 1)
		WARNING("lock %p is already locked", lock);

	if (in_atomic() || irqs_disabled())
	{
		spin_lock(&lock->spinlock);
		lock->in_bh = 0;
	}
	else
	{
		spin_lock_bh(&lock->spinlock);
		lock->in_bh = 1;
	}
	atomic_set(&lock->in_use, 1);
	TRACEEXIT5(return);
}

static inline void wrap_spin_unlock(struct wrap_spinlock *lock)
{
	TRACEENTER5("lock: %p", lock);
	if (lock->magic != NDIS_SPIN_LOCK_MAGIC)
		WARNING("lock %p is not initlialized (%d)", lock, lock->magic);
	if (atomic_read(&lock->in_use) == 0)
		WARNING("lock %p was not locked", lock);

	atomic_set(&lock->in_use, 0);
	if (lock->in_bh)
		spin_unlock_bh(&lock->spinlock);
	else
		spin_unlock(&lock->spinlock);
	TRACEEXIT5(return);
}

#endif // NDISWRAPPER_H
