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

#ifndef _NTOSKERNEL_H_
#define _NTOSKERNEL_H_

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
#include <linux/spinlock.h>
#include <asm/mman.h>
#include <asm/atomic.h>

#include <linux/version.h>

#include "winnt_types.h"
#include "ndiswrapper.h"
#include "winnt_pe.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
#include <linux/kthread.h>
#endif

#if !defined(CONFIG_USB) && defined(CONFIG_USB_MODULE)
#define CONFIG_USB 1
#endif

#define addr_offset(driver) (__builtin_return_address(0) - (driver)->entry)

/* Workqueue / task queue backwards compatibility stuff */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
/* pci functions in 2.6 kernels have problems allocating dma buffers,
 * but seem to work fine with dma functions
 */
typedef struct workqueue_struct *workqueue;
#include <asm/dma-mapping.h>
#include <linux/scatterlist.h>

#define PCI_DMA_ALLOC_COHERENT(pci_dev,size,dma_handle) \
	dma_alloc_coherent(&pci_dev->dev,size,dma_handle, \
			   GFP_KERNEL | __GFP_REPEAT)
#define PCI_DMA_FREE_COHERENT(pci_dev,size,cpu_addr,dma_handle) \
	dma_free_coherent(&pci_dev->dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(pci_dev,addr,size,direction) \
	dma_map_single(&pci_dev->dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(pci_dev,dma_handle,size,direction) \
	dma_unmap_single(&pci_dev->dev,dma_handle,size,direction)
#define MAP_SG(pci_dev, sglist, nents, direction) \
	dma_map_sg(&pci_dev->dev, sglist, nents, direction)
#define UNMAP_SG(pci_dev, sglist, nents, direction) \
	dma_unmap_sg(&pci_dev->dev, sglist, nents, direction)

#else // linux version <= 2.5.41

#define PCI_DMA_ALLOC_COHERENT(dev,size,dma_handle) \
	pci_alloc_consistent(dev,size,dma_handle)
#define PCI_DMA_FREE_COHERENT(dev,size,cpu_addr,dma_handle) \
	pci_free_consistent(dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(dev,addr,size,direction) \
	pci_map_single(dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(dev,dma_handle,size,direction) \
	pci_unmap_single(dev,dma_handle,size,direction)
#define sg_init_one(sg, addr, len) do {			 \
		(sg)->page = virt_to_page(addr);		 \
		(sg)->offset = (unsigned long)addr & ~PAGE_MASK; \
		(sg)->length = len;				 \
	} while (0)
#define MAP_SG(dev, sglist, nents, direction) \
	pci_map_sg(dev, sglist, nents, direction)
#define UNMAP_SG(dev, sglist, nents, direction) \
	pci_unmap_sg(dev, sglist, nents, direction)
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define DECLARE_WORK(n, f, d) struct tq_struct n = { \
	list: LIST_HEAD_INIT(n.list), \
	sync: 0, \
	routine: f, \
	data: d \
}
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

#ifndef in_atomic
#ifdef CONFIG_PREEMPT
#define in_atomic() ((preempt_get_count() & ~PREEMPT_ACTIVE) != kernel_locked())
#else
#define in_atomic() (in_interrupt())
#endif // CONFIG_PREEMPT
#endif // in_atomic

#define __GFP_NOWARN 0

#endif // LINUX_VERSION_CODE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
#define HAVE_ETHTOOL 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifndef preempt_enable
#define preempt_enable()  (void)0
#endif
#ifndef preempt_disable
#define preempt_disable() (void)0
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#ifndef virt_addr_valid
#define virt_addr_valid(addr) VALID_PAGE(virt_to_page(addr))
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net,pdev) do { } while (0)
#endif

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#ifdef CONFIG_SOFTWARE_SUSPEND2
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,0,c)
#else
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,c)
#endif

#ifdef CONFIG_X86_64
#define LIN2WIN1(func, arg1) \
  lin_to_win1(func, (unsigned long)arg1)
#define LIN2WIN2(func, arg1, arg2) \
  lin_to_win2(func, (unsigned long)arg1, (unsigned long)arg2)
#define LIN2WIN3(func, arg1, arg2, arg3) \
  lin_to_win3(func, (unsigned long)arg1, (unsigned long)arg2, \
	      (unsigned long)arg3)
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)		      \
  lin_to_win4(func, (unsigned long)arg1, (unsigned long)arg2, \
	      (unsigned long)arg3, (unsigned long)arg4)
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)	      \
  lin_to_win5(func, (unsigned long)arg1, (unsigned long)arg2, \
	      (unsigned long)arg3, (unsigned long)arg4, (unsigned long)arg5)
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)	      \
  lin_to_win6(func, (unsigned long)arg1, (unsigned long)arg2, \
	      (unsigned long)arg3, (unsigned long)arg4, (unsigned long)arg5, \
	      (unsigned long)arg6)
#else
#define LIN2WIN1(func, arg1) func(arg1)
#define LIN2WIN2(func, arg1, arg2) func(arg1, arg2)
#define LIN2WIN3(func, arg1, arg2, arg3) func(arg1, arg2, arg3)
#define LIN2WIN4(func, arg1, arg2, arg3, arg4) func(arg1, arg2, arg3, arg4)
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5) \
  func(arg1, arg2, arg3, arg4, arg5)
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6) \
  func(arg1, arg2, arg3, arg4, arg5, arg6)
#endif

#ifndef __wait_event_interruptible_timeout
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
#endif

#ifndef wait_event_interruptible_timeout
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

#ifndef __wait_event_timeout
#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_UNINTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)
#endif

#ifndef wait_event_timeout
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_timeout(wq, condition, __ret);		\
	 __ret;								\
})
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

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
#define NW_MODULE_PARM_INT(name, perm) module_param(name, int, perm)
#define NW_MODULE_PARM_STRING(name, perm) module_param(name, charp, perm)
#else
#define NW_MODULE_PARM_INT(name, perm) MODULE_PARM(name, "i")
#define NW_MODULE_PARM_STRING(name, perm) MODULE_PARM(name, "s")
#endif

/* this ugly hack is to handle RH kernels; I don't know any better,
 * but this has to be fixed soon */
#ifndef rt_task
#define rt_task(p) ((p)->prio < MAX_RT_PRIO)
#endif

#define KMALLOC_THRESHOLD 131072

/* TICK is 100ns */
#define TICKSPERSEC             10000000
#define SECSPERDAY              86400

/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970       ((369 * 365 + 89) * (u64)SECSPERDAY)
#define TICKS_1601_TO_1970      (SECS_1601_TO_1970 * TICKSPERSEC)

#define UNIMPL() do {							\
		printk(KERN_ERR "%s --UNIMPLEMENTED--\n", __FUNCTION__ ); \
	} while (0)

typedef void (*WRAP_EXPORT_FUNC)(void);

struct wrap_export {
	const char *name;
	WRAP_EXPORT_FUNC func;
};

#ifdef CONFIG_X86_64
#define WRAP_EXPORT_SYMBOL(f) {#f, (WRAP_EXPORT_FUNC)x86_64_ ## f}
#define WRAP_EXPORT_WIN_FUNC(f) {#f, (WRAP_EXPORT_FUNC)x86_64__win_ ## f}
#define X86_64_STUB(f) x86_64_ ## f
#else
#define WRAP_EXPORT_SYMBOL(f) {#f, (WRAP_EXPORT_FUNC)f}
#define WRAP_EXPORT_WIN_FUNC(f) {#f, (WRAP_EXPORT_FUNC)_win_ ## f}
#define X86_64_STUB(f) f
#endif
/* map name s to function f - if f is different from s */
#define WRAP_EXPORT_MAP(s,f)
#define WRAP_EXPORT(x) x

struct wrap_alloc {
	struct list_head list;
	void *ptr;
};

struct pe_image {
	char name[MAX_DRIVER_NAME_LEN];
	void *entry;
	void *image;
	int size;
	int type;

	IMAGE_NT_HEADERS *nt_hdr;
	IMAGE_OPTIONAL_HEADER *opt_hdr;
};

extern struct wrap_spinlock atomic_lock;
extern struct wrap_spinlock cancel_lock;

#define DEBUG_IRQL 1

#define WRAPPER_SPIN_LOCK_MAGIC 137

#define WRAPPER_TIMER_MAGIC 47697249
struct wrapper_timer {
	struct list_head list;
	struct timer_list timer;
#ifdef DEBUG_TIMER
	unsigned long wrapper_timer_magic;
#endif
	long repeat;
	int active;
	struct ktimer *ktimer;
	struct kdpc *kdpc;
	struct wrap_spinlock lock;
};

int load_pe_images(struct pe_image[], int n);

void *wrap_kmalloc(size_t size, int flags);
void wrap_kfree(void *ptr);
void wrap_kfree_all(void);

void wrapper_init_timer(struct ktimer *ktimer, void *handle);
int wrapper_set_timer(struct wrapper_timer *wrapper_timer,
                      unsigned long expires, unsigned long repeat,
                      struct kdpc *kdpc);
void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer, char *canceled);
STDCALL void KeInitializeEvent(struct kevent *kevent,
			       enum event_type type, BOOLEAN state);
STDCALL LONG KeSetEvent(struct kevent *kevent, KPRIORITY incr, BOOLEAN wait);
STDCALL LONG KeResetEvent(struct kevent *kevent);
STDCALL NT_STATUS KeWaitForSingleObject(void *object, KWAIT_REASON reason,
					KPROCESSOR_MODE waitmode,
					BOOLEAN alertable,
					LARGE_INTEGER *timeout);
ULONGLONG ticks_1601(void);

STDCALL KIRQL KeGetCurrentIrql(void);
STDCALL void KeInitializeSpinLock(KSPIN_LOCK *lock);
STDCALL void KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql);
STDCALL void KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL oldirql);
STDCALL KIRQL KeAcquireSpinLockRaiseToDpc(KSPIN_LOCK *lock);

_FASTCALL KIRQL KfRaiseIrql(FASTCALL_DECL_1(KIRQL newirql));
_FASTCALL void KfLowerIrql(FASTCALL_DECL_1(KIRQL oldirql));
_FASTCALL KIRQL KfAcquireSpinLock(FASTCALL_DECL_1(KSPIN_LOCK *lock));
_FASTCALL void
KfReleaseSpinLock(FASTCALL_DECL_2(KSPIN_LOCK *lock, KIRQL oldirql));
_FASTCALL void
IofCompleteRequest(FASTCALL_DECL_2(struct irp *irp, CHAR prio_boost));
_FASTCALL void
KefReleaseSpinLockFromDpcLevel(FASTCALL_DECL_1(KSPIN_LOCK *lock));

void dump_bytes(const char *where, const u8 *ip);

unsigned long lin_to_win1(void *func, unsigned long);
unsigned long lin_to_win2(void *func, unsigned long, unsigned long);
unsigned long lin_to_win3(void *func, unsigned long, unsigned long,
			  unsigned long);
unsigned long lin_to_win4(void *func, unsigned long, unsigned long,
			  unsigned long, unsigned long);
unsigned long lin_to_win5(void *func, unsigned long, unsigned long,
			  unsigned long, unsigned long, unsigned long);
unsigned long lin_to_win6(void *func, unsigned long, unsigned long,
			  unsigned long, unsigned long, unsigned long,
			  unsigned long);

#define raise_irql(irql) KfRaiseIrql(FASTCALL_ARGS_1(irql))
#define lower_irql(irql) KfLowerIrql(FASTCALL_ARGS_1(irql))

#define MSG(level, fmt, ...) printk(level "ndiswrapper (%s:%d): " fmt "\n", \
				    __FUNCTION__, __LINE__ , ## __VA_ARGS__)
#define WARNING(fmt, ...) MSG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MSG(KERN_ERR, fmt , ## __VA_ARGS__)
#define INFO(fmt, ...) MSG(KERN_INFO, fmt , ## __VA_ARGS__)

#define check_spin_lock_size(lock) do {				\
		if (sizeof(lock) > sizeof(ULONG_PTR)) {		\
			ERROR("spinlock used is not compatible with "	\
			      "KSPIN_LOCK; is CONFIG_DEBUG_SPINLOCK "	\
			      "disabled? %u, %u",			\
			      (unsigned int)sizeof(lock),		\
			      (unsigned int)sizeof(ULONG_PTR));		\
		}							\
	} while (0)

static inline void wrap_spin_lock_init(struct wrap_spinlock *lock)
{
#ifndef CONFIG_DEBUG_SPINLOCK
	check_spin_lock_size(lock->klock);
#endif
	spin_lock_init(WRAP_SPINLOCK(lock));
	lock->use_bh = 0;
}

#define wrap_spin_lock(lock, irql) do {		\
		if (irql == DISPATCH_LEVEL) {			\
			if (KeGetCurrentIrql() == DISPATCH_LEVEL) {	\
				spin_lock(WRAP_SPINLOCK(lock));		\
				(lock)->use_bh = 0;			\
			} else {					\
				spin_lock_bh(WRAP_SPINLOCK(lock));	\
				(lock)->use_bh = 1;			\
			}						\
			if (!in_atomic())				\
				WARNING("!in_atomic()");		\
		} else {						\
			spin_lock(WRAP_SPINLOCK(lock));			\
			(lock)->use_bh = 0;				\
		}							\
	} while (0)

#define wrap_spin_unlock(lock) do {				\
		if ((lock)->use_bh) {				\
			if (!in_atomic())			\
				WARNING("!in_atomic()");	\
			spin_unlock_bh(WRAP_SPINLOCK(lock));	\
		} else {					\
			spin_unlock(WRAP_SPINLOCK(lock));	\
		}						\
	} while (0)

static inline void wrapper_set_timer_dpc(struct wrapper_timer *wrapper_timer,
                                         struct kdpc *kdpc)
{
	wrapper_timer->kdpc = kdpc;
}

static inline void init_dpc(struct kdpc *kdpc, void *func, void *ctx)
{
	kdpc->func = func;
	kdpc->ctx  = ctx;
}

static inline ULONG SPAN_PAGES(ULONG_PTR ptr, SIZE_T length)
{
	ULONG_PTR start, end;
	ULONG n;

	start = ptr & (PAGE_SIZE - 1);
	end = (ptr + length + PAGE_SIZE - 1) & PAGE_MASK;
	n = (end - start) / PAGE_SIZE;

	n = ((ULONG)(((ptr & (PAGE_SIZE -1)) + (length) + (PAGE_SIZE - 1)) >> PAGE_SHIFT));

	return n;
}

/* DEBUG macros */

#define DBGTRACE(fmt, ...) (void)0
#define DBGTRACE1(fmt, ...) (void)0
#define DBGTRACE2(fmt, ...) (void)0
#define DBGTRACE3(fmt, ...) (void)0
#define DBGTRACE4(fmt, ...) (void)0
#define DBGTRACE5(fmt, ...) (void)0

/* for a block of code */
#define DBG_BLOCK() while (0)

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(fmt, ...) printk(KERN_INFO "ndiswrapper (%s:%d): " fmt "\n", \
				  __FUNCTION__, __LINE__ , ## __VA_ARGS__)
#undef DBG_BLOCK
#define DBG_BLOCK()
#endif

#if defined DEBUG && DEBUG >= 1
#undef DBGTRACE1
#define DBGTRACE1(fmt, ...) DBGTRACE(fmt , ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 2
#undef DBGTRACE2
#define DBGTRACE2(fmt, ...) DBGTRACE(fmt , ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 3
#undef DBGTRACE3
#define DBGTRACE3(fmt, ...) DBGTRACE(fmt , ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 4
#undef DBGTRACE4
#define DBGTRACE4(fmt, ...) DBGTRACE(fmt , ## __VA_ARGS__)
#endif

#if defined DEBUG && DEBUG >= 5
#undef DBGTRACE5
#define DBGTRACE5(fmt, ...) DBGTRACE(fmt , ## __VA_ARGS__)
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

#if defined DEBUG
#define ASSERT(expr) do {						\
		if (!(expr)) {						\
			ERROR("Assertion failed! %s\n", (#expr));	\
		}							\
	} while (0)
#else
#define ASSERT(expr)
#endif

#endif // _NTOSKERNEL_H_
