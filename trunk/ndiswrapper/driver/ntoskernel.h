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

#define UTILS_VERSION "1.2"

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/time.h>

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
#include <linux/list.h>
#include <linux/sched.h>

#include <linux/spinlock.h>
#include <asm/mman.h>

#include <linux/version.h>

#include "winnt_types.h"
#include "ndiswrapper.h"
#include "pe_linker.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
#include <linux/kthread.h>
#endif

#if !defined(CONFIG_USB) && defined(CONFIG_USB_MODULE)
#define CONFIG_USB 1
#endif

#define addr_offset(drvr) (__builtin_return_address(0) - \
			     (drvr)->drv_obj->driver_start)

/* Workqueue / task queue backwards compatibility stuff */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
/* pci functions in 2.6 kernels have problems allocating dma buffers,
 * but seem to work fine with dma functions
 */
typedef struct workqueue_struct *workqueue;
#include <asm/dma-mapping.h>

#define PCI_DMA_ALLOC_COHERENT(pci_dev,size,dma_handle) \
	dma_alloc_coherent(&pci_dev->dev,size,dma_handle, \
			   GFP_KERNEL | __GFP_REPEAT | GFP_DMA)
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
#define MAP_SG(dev, sglist, nents, direction) \
	pci_map_sg(dev, sglist, nents, direction)
#define UNMAP_SG(dev, sglist, nents, direction) \
	pci_unmap_sg(dev, sglist, nents, direction)
#include <linux/tqueue.h>
#define work_struct tq_struct
#define INIT_WORK INIT_TQUEUE
#define DECLARE_WORK(n, f, d) struct tq_struct n = { \
		list: LIST_HEAD_INIT(n.list),	     \
		sync: 0,			     \
		routine: f,			     \
		data: d				     \
}
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
typedef task_queue workqueue;
#include <linux/smp_lock.h>

/* RedHat kernels #define irqs_disabled this way */
#ifndef irqs_disabled
#define irqs_disabled()                \
({                                     \
	unsigned long flags;	       \
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

#ifndef offset_in_page
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#include <linux/scatterlist.h>
#else
#define sg_init_one(sg, addr, len) do {				 \
		(sg)->page = virt_to_page(addr);		 \
		(sg)->offset = offset_in_page(addr);		 \
		(sg)->length = len;				 \
	} while (0)
#endif // KERNEL_VERSION(2,6,9)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
#define HAVE_ETHTOOL 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifndef preempt_enable
#define preempt_enable()  do { } while (0)
#endif
#ifndef preempt_disable
#define preempt_disable() do { } while (0)
#endif

#ifndef container_of
#define container_of(ptr, type, member)					\
({									\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );		\
})
#endif

#ifndef virt_addr_valid
#define virt_addr_valid(addr) VALID_PAGE(virt_to_page(addr))
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net,pdev) do { } while (0)
#endif

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#ifndef PMSG_SUSPEND
#define PMSG_ON 0
#define PMSG_SUSPEND 3
typedef u32 pm_message_t;
#endif

#if defined(CONFIG_SOFTWARE_SUSPEND2) || defined(CONFIG_SUSPEND2)
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,0,c)
#define KTHREAD_CREATE(a,b,c) kthread_run(a,b,0,c)
#else
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,c)
#define KTHREAD_CREATE(a,b,c) kthread_run(a,b,c)
#endif

#ifdef CONFIG_X86_64
#define LIN2WIN1(func, arg1)			\
	lin_to_win1(func, (unsigned long)arg1)
#define LIN2WIN2(func, arg1, arg2)					\
	lin_to_win2(func, (unsigned long)arg1, (unsigned long)arg2)
#define LIN2WIN3(func, arg1, arg2, arg3)				\
	lin_to_win3(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3)
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
	lin_to_win4(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4)
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
	lin_to_win5(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4,		\
		    (unsigned long)arg5)
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
	lin_to_win6(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4,		\
		    (unsigned long)arg5, (unsigned long)arg6)
#else
#define LIN2WIN1(func, arg1) func(arg1)
#define LIN2WIN2(func, arg1, arg2) func(arg1, arg2)
#define LIN2WIN3(func, arg1, arg2, arg3) func(arg1, arg2, arg3)
#define LIN2WIN4(func, arg1, arg2, arg3, arg4) func(arg1, arg2, arg3, arg4)
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)	\
	func(arg1, arg2, arg3, arg4, arg5)
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)	\
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
#define TICKSPERSEC		10000000
#define TICKSPERMSEC		10000
#define SECSPERDAY		86400
#define SECSPERHOUR		3600
#define SECSPERMIN		60
#define DAYSPERWEEK		7

/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970	((369 * 365 + 89) * (u64)SECSPERDAY)
#define TICKS_1601_TO_1970	(SECS_1601_TO_1970 * TICKSPERSEC)

typedef void (*WRAP_EXPORT_FUNC)(void);

struct wrap_export {
	const char *name;
	WRAP_EXPORT_FUNC func;
};

#ifdef CONFIG_X86_64
#define WRAP_EXPORT_SYMBOL(f) {#f, (WRAP_EXPORT_FUNC)x86_64_ ## f}
#define WRAP_EXPORT_WIN_FUNC(f) {#f, (WRAP_EXPORT_FUNC)x86_64__win_ ## f}
#define WRAP_FUNC_PTR(f) &x86_64_ ## f
#define WRAP_FUNC_PTR_DECL(f) void x86_64_ ## f(void);
#else
#define WRAP_EXPORT_SYMBOL(f) {#f, (WRAP_EXPORT_FUNC)f}
#define WRAP_EXPORT_WIN_FUNC(f) {#f, (WRAP_EXPORT_FUNC)_win_ ## f}
#define WRAP_FUNC_PTR(f) &f
#define WRAP_FUNC_PTR_DECL(f)
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

extern KSPIN_LOCK atomic_lock;
extern KSPIN_LOCK cancel_lock;

#define DEBUG_IRQL 1

#define WRAPPER_TIMER_MAGIC 47697249
struct wrapper_timer {
	/* wrapper_timer replaces kdpc field in ktimer; if some
	 * (nasty) driver passes ktimer->kdpc to other functions,
	 * having kdpc as first field of wrapper_timer will work as
	 * expected */
	struct kdpc *kdpc;
	struct nt_list list;
	struct timer_list timer;
	struct ktimer *ktimer;
#ifdef DEBUG_TIMER
	unsigned long wrapper_timer_magic;
#endif
	long repeat;
	int active;
	KSPIN_LOCK lock;
	/* kdpc's associated with kernel timers should be inserted
	 * into kdpc when timer expires and kdpc's associated with
	 * NDIS timers should be executed when timer expires */
	BOOLEAN kernel_timer;
};

typedef struct mdl ndis_buffer;

struct phys_dev {
	int dev_type;
	struct pci_dev *pci;
	struct usb_device *usb;
};

int ntoskernel_init(void);
void ntoskernel_exit(void);
struct driver_object *find_bus_driver(const char *name);
struct device_object *alloc_pdo(struct driver_object *drv_obj);

STDCALL void *ExAllocatePoolWithTag(enum pool_type pool_type, SIZE_T size,
				    ULONG tag);
STDCALL void ExFreePool(void *p);
STDCALL ULONG MmSizeOfMdl(void *base, ULONG length);
STDCALL void KeInitializeEvent(struct kevent *kevent,
			       enum event_type type, BOOLEAN state);
STDCALL LONG KeSetEvent(struct kevent *kevent, KPRIORITY incr, BOOLEAN wait);
STDCALL LONG KeResetEvent(struct kevent *kevent);
STDCALL void KeClearEvent(struct kevent *kevent);
STDCALL void KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx);
BOOLEAN insert_kdpc_work(struct kdpc *kdpc, BOOLEAN dup_check);
BOOLEAN remove_kdpc_work(struct kdpc *kdpc);
STDCALL BOOLEAN KeInsertQueueDpc(struct kdpc *kdpc, void *arg1, void *arg2);
STDCALL BOOLEAN KeRemoveQueueDpc(struct kdpc *kdpc);
STDCALL NTSTATUS KeWaitForSingleObject(struct kevent *object,
				       KWAIT_REASON reason,
				       KPROCESSOR_MODE waitmode,
				       BOOLEAN alertable,
				       LARGE_INTEGER *timeout);
struct mdl *allocate_init_mdl(void *virt, ULONG length);
void free_mdl(struct mdl *mdl);
STDCALL struct mdl *IoAllocateMdl(void *virt, ULONG length, BOOLEAN second_buf,
				  BOOLEAN charge_quota, struct irp *irp);
STDCALL void IoFreeMdl(struct mdl *mdl);
STDCALL void NdisFreeBuffer(ndis_buffer *buffer);
_FASTCALL LONG InterlockedDecrement(FASTCALL_DECL_1(LONG volatile *val));
_FASTCALL LONG InterlockedIncrement(FASTCALL_DECL_1(LONG volatile *val));
_FASTCALL struct nt_list *
ExInterlockedInsertHeadList(FASTCALL_DECL_3(struct nt_list *head,
					    struct nt_list *entry,
					    KSPIN_LOCK *lock));
_FASTCALL struct nt_list *
ExInterlockedInsertTailList(FASTCALL_DECL_3(struct nt_list *head,
					    struct nt_list *entry,
					    KSPIN_LOCK *lock));
_FASTCALL struct nt_list *
ExInterlockedRemoveHeadList(FASTCALL_DECL_2(struct nt_list *head,
					    KSPIN_LOCK *lock));
STDCALL NTSTATUS IoCreateDevice(struct driver_object *driver,
				ULONG dev_ext_length,
				struct unicode_string *dev_name,
				DEVICE_TYPE dev_type,
				ULONG dev_chars, BOOLEAN exclusive,
				struct device_object **dev_obj);
STDCALL void IoDeleteDevice(struct device_object *dev);
STDCALL void IoDetachDevice(struct device_object *topdev);
STDCALL NTSTATUS
IoAllocateDriverObjectExtension(struct driver_object *drv_obj,
				void *client_id, ULONG extlen, void **ext);
STDCALL void *IoGetDriverObjectExtension(struct driver_object *drv,
					 void *client_id);
STDCALL struct device_object *IoAttachDeviceToDeviceStack
	(struct device_object *src, struct device_object *dst);
STDCALL void KeInitializeEvent(struct kevent *kevent, enum event_type type,
			       BOOLEAN state);
void free_custom_ext(struct driver_extension *drv_obj_ext);
STDCALL NTSTATUS AddDevice(struct driver_object *drv_obj,
			   struct device_object *pdo);
driver_dispatch_t IopInvalidDeviceRequest;
driver_dispatch_t IopPassIrpDown;
driver_dispatch_t pdoDispatchInternalDeviceControl;
driver_dispatch_t pdoDispatchDeviceControl;
driver_dispatch_t pdoDispatchPnp;
driver_dispatch_t pdoDispatchPower;
driver_dispatch_t IopPassIrpDownAndWait;
driver_dispatch_t fdoDispatchPnp;

STDCALL struct irp *IoAllocateIrp(char stack_size, BOOLEAN charge_quota);
STDCALL void IoFreeIrp(struct irp *irp);
_FASTCALL NTSTATUS IofCallDriver
	(FASTCALL_DECL_2(struct device_object *dev_obj, struct irp *irp));
STDCALL struct irp *WRAP_EXPORT(IoBuildSynchronousFsdRequest)
	(ULONG major_func, struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset, struct kevent *event,
	 struct io_status_block *status);
STDCALL struct irp *WRAP_EXPORT(IoBuildAsynchronousFsdRequest)
	(ULONG major_func, struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset,
	 struct io_status_block *status);
STDCALL NTSTATUS PoCallDriver(struct device_object *dev_obj, struct irp *irp);

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
STDCALL void RtlCopyMemory(void *dst, const void *src, SIZE_T length);
STDCALL NTSTATUS RtlUnicodeStringToAnsiString(struct ansi_string *dst,
					       struct unicode_string *src,
					       BOOLEAN dup);
STDCALL NTSTATUS RtlAnsiStringToUnicodeString(struct unicode_string *dst,
					       struct ansi_string *src,
					       BOOLEAN dup);
STDCALL void RtlInitAnsiString(struct ansi_string *dst, CHAR *src);
STDCALL void RtlInitString(struct ansi_string *dst, CHAR *src);
STDCALL void RtlInitUnicodeString(struct unicode_string *dest,
				  const wchar_t *src);
STDCALL void RtlFreeUnicodeString(struct unicode_string *string);
STDCALL void RtlFreeAnsiString(struct ansi_string *string);

void *wrap_kmalloc(size_t size, int flags);
void wrap_kfree(void *ptr);
void wrapper_init_timer(struct ktimer *ktimer, void *handle,
			struct kdpc *kdpc);
int wrapper_set_timer(struct wrapper_timer *wrapper_timer,
		      unsigned long expires, unsigned long repeat,
		      struct kdpc *kdpc, BOOLEAN kernel_timer);
void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer,
			  BOOLEAN *canceled);

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

STDCALL struct kthread *KeGetCurrentThread(void);
STDCALL NTSTATUS
ObReferenceObjectByHandle(void *handle, ACCESS_MASK desired_access,
			  void *obj_type, KPROCESSOR_MODE access_mode,
			  void **object, void *handle_info);

_FASTCALL LONG ObfReferenceObject(FASTCALL_DECL_1(void *object));
_FASTCALL void ObfDereferenceObject(FASTCALL_DECL_1(void *object));
STDCALL NTSTATUS ZwClose(void *object);
#define ObReferenceObject(object)  \
	ObfReferenceObject(FASTCALL_ARGS_1(object))
#define ObDereferenceObject(object)  \
	ObfDereferenceObject(FASTCALL_ARGS_1(object))

#define MSG(level, fmt, ...)				\
	printk(level "ndiswrapper (%s:%d): " fmt "\n",	\
	       __FUNCTION__, __LINE__ , ## __VA_ARGS__)
#define WARNING(fmt, ...) MSG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MSG(KERN_ERR, fmt , ## __VA_ARGS__)
#define INFO(fmt, ...) MSG(KERN_INFO, fmt , ## __VA_ARGS__)

#define INFOEXIT(stmt) do { INFO("Exit"); stmt; } while(0)

#define UNIMPL() ERROR("--UNIMPLEMENTED--")

void adjust_user_shared_data_addr(char *driver, unsigned long length);

#define IoCompleteRequest(irp, prio) \
	IofCompleteRequest(FASTCALL_ARGS_2(irp, prio));
#define IoCallDriver(dev, irp) \
	IofCallDriver(FASTCALL_ARGS_2(dev, irp));

static inline KIRQL current_irql(void)
{
	if (in_atomic() || irqs_disabled())
		return DISPATCH_LEVEL;
	else
		return PASSIVE_LEVEL;
}

static inline KIRQL raise_irql(KIRQL newirql)
{
	KIRQL irql = current_irql();
	if (irql < DISPATCH_LEVEL && newirql >= DISPATCH_LEVEL) {
		local_bh_disable();
		preempt_disable();
	}
	return irql;
}

static inline void lower_irql(KIRQL oldirql)
{
	KIRQL irql = current_irql();
	if (oldirql < DISPATCH_LEVEL && irql >= DISPATCH_LEVEL) {
		preempt_enable();
		local_bh_enable();
	}
}

/* Windows spinlocks are of type ULONG_PTR which is not big enough to
 * store Linux spinlocks; so we implement Windows spinlocks using
 * ULONG_PTR space with our own functions/macros */

/* the reason for value of unlocked spinlock to be 0, instead of 1
 * (which is what linux spinlocks use), is that some drivers don't
 * first call to initialize spinlock; in those case, the value of the
 * lock seems to be 0 (presumably in Windows value of unlocked
 * spinlock is 0).
 */
#define KSPIN_LOCK_UNLOCKED 0
#define KSPIN_LOCK_LOCKED 1

#define kspin_lock_init(lock) *(lock) = KSPIN_LOCK_UNLOCKED

#ifdef CONFIG_SMP

#ifdef __HAVE_ARCH_CMPXCHG

#define kspin_lock(lock)						\
	while (cmpxchg(lock, KSPIN_LOCK_UNLOCKED, KSPIN_LOCK_LOCKED) != \
	       KSPIN_LOCK_UNLOCKED)

#else

extern spinlock_t spinlock_kspin_lock;
#define kspin_lock(lock)				\
do {							\
	while (1) {					\
		spin_lock(&spinlock_kspin_lock);	\
		if (*(lock) == KSPIN_LOCK_UNLOCKED)	\
			break;				\
		spin_unlock(&spinlock_kspin_lock);	\
	}						\
	*(lock) = KSPIN_LOCK_LOCKED;			\
	spin_unlock(&spinlock_kspin_lock);		\
} while (0)

#endif // __HAVE_ARCH_CMPXCHG

#define kspin_unlock(lock) xchg(lock, KSPIN_LOCK_UNLOCKED)

#else

#define kspin_lock(lock) *(lock) = KSPIN_LOCK_LOCKED
#define kspin_unlock(lock) *(lock) = KSPIN_LOCK_UNLOCKED

#endif // CONFIG_SMP

/* raise IRQL to given (higher) IRQL if necessary before locking */
#define kspin_lock_irql(lock, newirql)					\
({									\
	KIRQL _cur_irql_ = current_irql();				\
	KSPIN_LOCK _val_ = *(lock);					\
	if (_val_ > KSPIN_LOCK_LOCKED)					\
		ERROR("illegal spinlock: %p(%lu)", lock, _val_);	\
	if (_cur_irql_ < DISPATCH_LEVEL && newirql == DISPATCH_LEVEL) {	\
		local_bh_disable();					\
		preempt_disable();					\
	}								\
	kspin_lock(lock);						\
	_cur_irql_;							\
})

/* lower IRQL to given (lower) IRQL if necessary after unlocking */
#define kspin_unlock_irql(lock, oldirql)				\
do {									\
	KIRQL _cur_irql_ = current_irql();				\
	KSPIN_LOCK _val_ = *(lock);					\
	if (_val_ > KSPIN_LOCK_LOCKED)					\
		ERROR("illegal spinlock: %p(%lu)", lock, _val_);	\
	kspin_unlock(lock);						\
	if (oldirql < DISPATCH_LEVEL && _cur_irql_ == DISPATCH_LEVEL) {	\
		preempt_enable();					\
		local_bh_enable();					\
	}								\
} while (0)

#define kspin_lock_irqsave(lock, flags)					\
do {									\
	KSPIN_LOCK _val_ = *(lock);					\
	if (_val_ > KSPIN_LOCK_LOCKED)					\
		ERROR("illegal spinlock: %p(%lu)", lock, _val_);	\
	local_irq_save(flags);						\
	preempt_disable();						\
	kspin_lock(lock);						\
} while (0)

#define kspin_unlock_irqrestore(lock, flags)				\
do {									\
	KSPIN_LOCK _val_ = *(lock);					\
	if (_val_ > KSPIN_LOCK_LOCKED)					\
		ERROR("illegal spinlock: %p(%lu)", lock, _val_);	\
	kspin_unlock(lock);						\
	local_irq_restore(flags);					\
	preempt_enable();						\
} while (0)

static inline ULONG SPAN_PAGES(ULONG_PTR ptr, SIZE_T length)
{
	ULONG n;

	n = (((ULONG_PTR)ptr & (PAGE_SIZE - 1)) +
	     length + (PAGE_SIZE - 1)) >> PAGE_SHIFT;

	return n;
}

/* DEBUG macros */

#define DBGTRACE(fmt, ...) do { } while (0)
#define DBGTRACE1(fmt, ...) do { } while (0)
#define DBGTRACE2(fmt, ...) do { } while (0)
#define DBGTRACE3(fmt, ...) do { }  while (0)
#define DBGTRACE4(fmt, ...) do { } while (0)
#define DBGTRACE5(fmt, ...) do { } while (0)
#define DBGTRACE6(fmt, ...) do { } while (0)

/* for a block of code */
#define DBG_BLOCK() while (0)

extern int debug;

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(level, fmt, ...) do {					\
		if (level <= debug)					\
			printk(KERN_INFO "%s (%s:%d): " fmt "\n",	\
			       DRIVER_NAME, __FUNCTION__,		\
			       __LINE__ , ## __VA_ARGS__);		\
	} while (0)
#undef DBG_BLOCK
#define DBG_BLOCK()
#endif

#if defined(DEBUG) && DEBUG >= 1
#undef DBGTRACE1
#define DBGTRACE1(fmt, ...) DBGTRACE(1, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 2
#undef DBGTRACE2
#define DBGTRACE2(fmt, ...) DBGTRACE(2, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 3
#undef DBGTRACE3
#define DBGTRACE3(fmt, ...) DBGTRACE(3, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 4
#undef DBGTRACE4
#define DBGTRACE4(fmt, ...) DBGTRACE(4, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 5
#undef DBGTRACE5
#define DBGTRACE5(fmt, ...) DBGTRACE(5, fmt , ## __VA_ARGS__)
#endif

#if defined(DEBUG) && DEBUG >= 6
#undef DBGTRACE6
#define DBGTRACE6(fmt, ...) DBGTRACE(6, fmt , ## __VA_ARGS__)
#endif

#define TRACEENTER(fmt, ...) DBGTRACE("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER1(fmt, ...) DBGTRACE1("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER2(fmt, ...) DBGTRACE2("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER3(fmt, ...) DBGTRACE3("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER4(fmt, ...) DBGTRACE4("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER5(fmt, ...) DBGTRACE5("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER6(fmt, ...) DBGTRACE6("Enter " fmt , ## __VA_ARGS__)

#define TRACEEXIT(stmt) do { DBGTRACE("Exit"); stmt; } while(0)
#define TRACEEXIT1(stmt) do { DBGTRACE1("Exit"); stmt; } while(0)
#define TRACEEXIT2(stmt) do { DBGTRACE2("Exit"); stmt; } while(0)
#define TRACEEXIT3(stmt) do { DBGTRACE3("Exit"); stmt; } while(0)
#define TRACEEXIT4(stmt) do { DBGTRACE4("Exit"); stmt; } while(0)
#define TRACEEXIT5(stmt) do { DBGTRACE5("Exit"); stmt; } while(0)
#define TRACEEXIT6(stmt) do { DBGTRACE6("Exit"); stmt; } while(0)

#define USB_DEBUG 1

#if defined(DEBUG) && defined(USB_DEBUG)
#define USBTRACE(fmt, ...) DBGTRACE1(fmt, ## __VA_ARGS__)
#define USBTRACEENTER(fmt, ...) TRACEENTER1(fmt, ## __VA_ARGS__)
#define USBTRACEEXIT(stmt) TRACEEXIT1(stmt)
#else
#define USBTRACE(fmt, ...)
#define USBTRACEENTER(fmt, ...)
#define USBTRACEEXIT(stmt) stmt
#endif

#if defined DEBUG
#define ASSERT(expr) do {						\
		if (!(expr)) {						\
			ERROR("Assertion failed! %s", (#expr));		\
		}							\
	} while (0)
#else
#define ASSERT(expr)
#endif

#if defined(DEBUG) && defined(USB_DEBUG)
#define DUMP_IRP(__irp)							\
	do {								\
		struct io_stack_location *_irp_sl;			\
		_irp_sl = IoGetCurrentIrpStackLocation(__irp);		\
		INFO("irp: %p, stack size: %d, cl: %d, sl: %p, "	\
		     "dev_obj: %p, mj_fn: %d, minor_fn: %d, nt_urb: %p", \
		     __irp, __irp->stack_count,	(__irp)->current_location, \
		     _irp_sl, _irp_sl->dev_obj, _irp_sl->major_fn,	\
		     _irp_sl->minor_fn, URB_FROM_IRP(__irp));		\
	} while (0)

#else
#define DUMP_IRP(__irp)
#endif

#endif // _NTOSKERNEL_H_
