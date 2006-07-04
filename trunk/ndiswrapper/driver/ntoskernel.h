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

#define UTILS_VERSION "1.8"

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/module.h>
#include <linux/kmod.h>

#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/pm.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/usb.h>
#include <linux/spinlock.h>
#include <asm/mman.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <net/iw_handler.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
#include <linux/kthread.h>
#endif
/* Interrupt backwards compatibility stuff */
#include <linux/interrupt.h>
#ifndef IRQ_HANDLED
#define IRQ_HANDLED
#define IRQ_NONE
#define irqreturn_t void
#endif

/* Workqueue / task queue backwards compatibility stuff */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,41)
#include <linux/workqueue.h>
/* pci functions in 2.6 kernels have problems allocating dma buffers,
 * but seem to work fine with dma functions
 */
typedef struct workqueue_struct *workqueue;
#include <asm/dma-mapping.h>

#define PCI_DMA_ALLOC_COHERENT(pci_dev,size,dma_handle)			\
	dma_alloc_coherent(&pci_dev->dev,size,dma_handle, GFP_KERNEL)
#define PCI_DMA_FREE_COHERENT(pci_dev,size,cpu_addr,dma_handle)		\
	dma_free_coherent(&pci_dev->dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(pci_dev,addr,size,direction)		\
	dma_map_single(&pci_dev->dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(pci_dev,dma_handle,size,direction)		\
	dma_unmap_single(&pci_dev->dev,dma_handle,size,direction)
#define MAP_SG(pci_dev, sglist, nents, direction)		\
	dma_map_sg(&pci_dev->dev, sglist, nents, direction)
#define UNMAP_SG(pci_dev, sglist, nents, direction)		\
	dma_unmap_sg(&pci_dev->dev, sglist, nents, direction)

#else // linux version <= 2.5.41

#define PCI_DMA_ALLOC_COHERENT(dev,size,dma_handle)	\
	pci_alloc_consistent(dev,size,dma_handle)
#define PCI_DMA_FREE_COHERENT(dev,size,cpu_addr,dma_handle)	\
	pci_free_consistent(dev,size,cpu_addr,dma_handle)
#define PCI_DMA_MAP_SINGLE(dev,addr,size,direction)	\
	pci_map_single(dev,addr,size,direction)
#define PCI_DMA_UNMAP_SINGLE(dev,dma_handle,size,direction)	\
	pci_unmap_single(dev,dma_handle,size,direction)
#define MAP_SG(dev, sglist, nents, direction)		\
	pci_map_sg(dev, sglist, nents, direction)
#define UNMAP_SG(dev, sglist, nents, direction)		\
	pci_unmap_sg(dev, sglist, nents, direction)

/* 2.4 kernels don't have workqueues, but we need them */
struct workqueue_struct {
	spinlock_t lock;
	wait_queue_head_t waitq_head;
	/* how many work_structs pending? */
	int pending;
	const char *name;
	int pid;
	/* list of work_structs pending */
	struct list_head work_list;
};

struct work_struct {
	struct list_head list;
	void (*func)(void *data);
	void *data;
	/* whether/on which workqueue scheduled */
	struct workqueue_struct *workq;
};	

#define INIT_WORK(work_struct, worker_func, worker_data)	\
	do {							\
		(work_struct)->func = worker_func;		\
		(work_struct)->data = worker_data;		\
		(work_struct)->workq = NULL;			\
	} while (0)

struct workqueue_struct *create_singlethread_workqueue(const char *name);
void destroy_workqueue(struct workqueue_struct *workq);
void queue_work(struct workqueue_struct *workq,
		struct work_struct *work_struct);
void cancel_delayed_work(struct work_struct *work_struct);

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
#define in_atomic()							\
	 ((preempt_get_count() & ~PREEMPT_ACTIVE) != 0)
#else
#define in_atomic() (in_interrupt())
#endif // CONFIG_PREEMPT
#endif // in_atomic

#endif // LINUX_VERSION_CODE

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

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
#define WRAP_MODULE_PARM_INT(name, perm) module_param(name, int, perm)
#define WRAP_MODULE_PARM_STRING(name, perm) module_param(name, charp, perm)
#else
#define WRAP_MODULE_PARM_INT(name, perm) MODULE_PARM(name, "i")
#define WRAP_MODULE_PARM_STRING(name, perm) MODULE_PARM(name, "s")
#endif

#ifndef LOCK_PREFIX
#ifdef LOCK
#define LOCK_PREFIX LOCK
#else
#ifdef CONFIG_SMP
#define LOCK_PREFIX "lock ; "
#else
#define LOCK_PREFIX ""
#endif
#endif
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif

/* this ugly hack is to handle RH kernels; I don't know any better,
 * but this has to be fixed soon */
#ifndef rt_task
#define rt_task(p) ((p)->prio < MAX_RT_PRIO)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifndef preempt_enable
#define preempt_enable()  do { } while (0)
#endif
#ifndef preempt_disable
#define preempt_disable() do { } while (0)
#endif

#ifndef preempt_enable_no_resched
#define preempt_enable_no_resched() preempt_enable()
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

#define usb_set_intfdata(intf, data) do { } while (0)

#endif // LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifndef offset_in_page
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,23)
#define HAVE_ETHTOOL 1
#endif

#ifndef PMSG_SUSPEND
#ifdef PM_SUSPEND
/* this is not correct - the value of PM_SUSPEND is different from
 * PMSG_SUSPEND, but ndiswrapper doesn't care about the value when
 * suspending */
#define PMSG_SUSPEND PM_SUSPEND
#define PSMG_ON PM_ON
#else
typedef u32 pm_message_t;
#define PMSG_SUSPEND 2
#define PMSG_ON 0
#endif
#endif

#ifndef PCI_D0
#define PCI_D0 0
#define PCI_D3hot 3
#endif

#ifndef PM_EVENT_SUSPEND
#define PM_EVENT_SUSPEND 2
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#define pci_choose_state(dev, state) (state)
#endif

#if defined(CONFIG_SOFTWARE_SUSPEND2) || defined(CONFIG_SUSPEND2)
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,0,c)
#else
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,c)
#endif

#if !defined(HAVE_NETDEV_PRIV)
#define netdev_priv(dev)  ((dev)->priv)
#endif

#include "winnt_types.h"
#include "ndiswrapper.h"
#include "pe_linker.h"
#include "wrapmem.h"

#define get_sp(sp) __asm__ __volatile__("mov %%esp, %0\n\t" : "=m"(sp))
#define print_sp() do {				\
		void *sp;			\
		get_sp(sp);			\
		INFO("sp: %p", sp);		\
	} while (0)

//#define DEBUG_IRQL 1

#if !defined(CONFIG_USB) && defined(CONFIG_USB_MODULE)
#define CONFIG_USB 1
#endif

#if defined(DISABLE_USB)
#undef CONFIG_USB
#undef CONFIG_USB_MODULE
#endif

#ifdef CONFIG_X86_64
#define LIN2WIN1(func, arg1)						\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win1(func, (unsigned long)arg1);				\
})
#define LIN2WIN2(func, arg1, arg2)					\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win2(func, (unsigned long)arg1, (unsigned long)arg2);	\
})
#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win3(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3);				\
})
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win4(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4);		\
})
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win5(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4,		\
		    (unsigned long)arg5);				\
})
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	DBGTRACE6("calling %p", func);					\
	lin_to_win6(func, (unsigned long)arg1, (unsigned long)arg2,	\
		    (unsigned long)arg3, (unsigned long)arg4,		\
		    (unsigned long)arg5, (unsigned long)arg6);		\
})

/* NOTE: these macros assume function arguments are quads and
 * arguments are not touched in any way before calling these macros */
#define WIN2LIN2(arg1, arg2)						\
do {									\
	__asm__ __volatile__("mov %%rcx, %0\n\t"			\
			     "mov %%rdx, %1\n\t"			\
			     : "=m" (arg1), "=m" (arg2));		\
} while (0)

#define WIN2LIN3(arg1, arg2, arg3)					\
do {									\
	__asm__ __volatile__("mov %%rcx, %0\n\t"			\
			     "mov %%rdx, %1\n\t"			\
			     "mov %%r8, %2\n\t"				\
			     : "=m" (arg1), "=m" (arg2), "=m" (arg3));	\
} while (0)

#else // CONFIG_X86_64

#define LIN2WIN1(func, arg1)						\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1);							\
})
#define LIN2WIN2(func, arg1, arg2)					\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2);						\
})
#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3);						\
})
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4);					\
})
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5);				\
})
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5, arg6);			\
})

#define WIN2LIN2(arg1, arg2) do { } while (0)

#define WIN2LIN3(arg1, arg2, arg3) do { } while (0)

#endif // CONFIG_X86_64

#define KMALLOC_THRESHOLD 130000

/* TICK is 100ns */
#define TICKSPERSEC		10000000LL
#define TICKSPERMSEC		10000
#define SECSPERDAY		86400
#define SECSPERHOUR		3600
#define SECSPERMIN		60
#define DAYSPERWEEK		7

/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970	((369 * 365 + 89) * (u64)SECSPERDAY)
#define TICKS_1601_TO_1970	(SECS_1601_TO_1970 * TICKSPERSEC)

/* 100ns units to HZ; if sys_time is negative, relative to current
 * clock, otherwise from year 1601 */
#define SYSTEM_TIME_TO_HZ(sys_time)					\
	((((sys_time) <= 0) ? (((u64)HZ * (-(sys_time))) / TICKSPERSEC) : \
	  (((s64)HZ * ((sys_time) - ticks_1601())) / TICKSPERSEC)))

#define MSEC_TO_HZ(ms) ((ms) * HZ / 1000)
#define USEC_TO_HZ(ms) ((us) * HZ / 1000000)

extern u64 wrap_ticks_to_boot;

static inline u64 ticks_1601(void)
{
	return wrap_ticks_to_boot + (u64)jiffies * TICKSPERSEC / HZ;
}

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

#define POOL_TAG(A, B, C, D)					\
	((ULONG)((A) + ((B) << 8) + ((C) << 16) + ((D) << 24)))

struct pe_image {
	char name[MAX_DRIVER_NAME_LEN];
	UINT (*entry)(struct driver_object *, struct unicode_string *) wstdcall;
	void *image;
	int size;
	int type;

	IMAGE_NT_HEADERS *nt_hdr;
	IMAGE_OPTIONAL_HEADER *opt_hdr;
};

struct ndis_miniport_block;

struct wrap_timer {
	long repeat;
	struct nt_list list;
	struct timer_list timer;
	struct nt_timer *nt_timer;
#ifdef TIMER_DEBUG
	unsigned long wrap_timer_magic;
#endif
};

struct ntos_work_item {
	struct nt_list list;
	void *arg1;
	void *arg2;
	void (*func)(void *arg1, void *arg2) wstdcall;
};

struct wrap_device_setting {
	struct nt_list list;
	char name[MAX_SETTING_NAME_LEN];
	char value[MAX_SETTING_VALUE_LEN];
	void *encoded;
};

struct wrap_bin_file {
	char driver_name[MAX_DRIVER_NAME_LEN];
	char name[MAX_DRIVER_NAME_LEN];
	int size;
	void *data;
};

#define WRAP_DRIVER_CLIENT_ID 1

struct wrap_driver {
	struct nt_list list;
	struct driver_object *drv_obj;
	char name[MAX_DRIVER_NAME_LEN];
	char version[MAX_SETTING_VALUE_LEN];
	unsigned int num_pe_images;
	struct pe_image pe_images[MAX_DRIVER_PE_IMAGES];
	int num_bin_files;
	struct wrap_bin_file *bin_files;
	struct nt_list wrap_devices;
	struct wrap_ndis_driver *ndis_driver;
};

struct wrap_device {
	/* first part is (de)initialized once by loader */
	int dev_bus_type;
	int vendor;
	int device;
	int subvendor;
	int subdevice;
	struct wrap_driver *driver;
	/* we need driver_name before driver is loaded */
	char driver_name[MAX_DRIVER_NAME_LEN];
	char conf_file_name[MAX_DRIVER_NAME_LEN];
	struct nt_list settings;

	/* rest should be (de)initialized when a device is
	 * (un)plugged */
	struct device_object *pdo;
	union {
		struct {
			struct pci_dev *pdev;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
			u32 pci_state[16];
#endif
		} pci;
		struct {
			struct usb_device *udev;
			struct usb_interface *intf;
			int num_alloc_urbs;
			struct nt_list wrap_urb_list;
		} usb;
	};
	union {
		struct wrap_ndis_device *wnd;
	};
	struct cm_resource_list *resource_list;
	BOOLEAN surprise_removed;
};

/* Some drivers use worker entries to complete functions called from
 * within other worker threads. So we should have separate workqueues
 * to make sure worker entries run properly */

#define USE_OWN_WORKQUEUE 1

#ifdef USE_OWN_WORKQUEUE

extern struct workqueue_struct *wrap_wq;
#define schedule_ndis_work(work_struct) queue_work(ndis_wq, (work_struct))
#define schedule_wrap_work(work_struct) queue_work(wrap_wq, (work_struct))

/* Normally workqueue for ntos is not required, as worker entries in
 * it are not supposed to wait; however, it helps to have separate
 * workqueue so keyboard etc. work when kernel crashes */

//#define USE_OWN_NTOS_WORKQUEUE 1

#ifdef USE_OWN_NTOS_WORKQUEUE
extern struct workqueue_struct *ntos_wq;
#define schedule_ntos_work(work_struct) queue_work(ntos_wq, (work_struct))
#else
#define schedule_ntos_work(work_struct) schedule_work(work_struct)
#endif

#else // USE_OWN_WORKQUEUE
#define schedule_ndis_work(work_struct) schedule_work(work_struct)
#define schedule_wrap_work(work_struct) schedule_work(work_struct)
#endif // USE_OWN_WORKQUEUE

int ntoskernel_init(void);
void ntoskernel_exit(void);
int ntoskernel_init_device(struct wrap_device *wd);
void ntoskernel_exit_device(struct wrap_device *wd);
void *allocate_object(ULONG size, enum common_object_type type, char *name);
void free_object(void *object);

int usb_init(void);
void usb_exit(void);
int usb_init_device(struct wrap_device *wd);
void usb_exit_device(struct wrap_device *wd);
void usb_cancel_pending_urbs(void);

int misc_funcs_init(void);
void misc_funcs_exit(void);

int wrap_procfs_init(void);
void wrap_procfs_remove(void);

int stricmp(const char *s1, const char *s2);
void dump_bytes(const char *name, const u8 *from, int len);

struct driver_object *find_bus_driver(const char *name);

wstdcall void WRITE_PORT_UCHAR(ULONG_PTR port, UCHAR value);
wstdcall UCHAR READ_PORT_UCHAR(ULONG_PTR port);

#undef ExAllocatePoolWithTag
wstdcall void *ExAllocatePoolWithTag(enum pool_type pool_type, SIZE_T size,
				    ULONG tag);
#if defined(ALLOC_DEBUG) && ALLOC_DEBUG > 1
#define ExAllocatePoolWithTag(pool_type, size, tag)			\
	wrap_ExAllocatePoolWithTag(pool_type, size, tag, __FILE__, __LINE__)
#endif

wstdcall void ExFreePool(void *p);
wstdcall ULONG MmSizeOfMdl(void *base, ULONG length);
wstdcall void *MmMapIoSpace(PHYSICAL_ADDRESS phys_addr, SIZE_T size,
			   enum memory_caching_type cache);
wstdcall void MmUnmapIoSpace(void *addr, SIZE_T size);
wstdcall void MmProbeAndLockPages(struct mdl *mdl, KPROCESSOR_MODE access_mode,
	 enum lock_operation operation);
wstdcall void MmUnlockPages(struct mdl *mdl);
wstdcall void KeInitializeEvent(struct nt_event *nt_event,
			       enum event_type type, BOOLEAN state);
wstdcall LONG KeSetEvent(struct nt_event *nt_event, KPRIORITY incr,
			BOOLEAN wait);
wstdcall LONG KeResetEvent(struct nt_event *nt_event);
wstdcall void KeClearEvent(struct nt_event *nt_event);
wstdcall void KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx);
wstdcall BOOLEAN KeInsertQueueDpc(struct kdpc *kdpc, void *arg1, void *arg2);
wstdcall BOOLEAN KeRemoveQueueDpc(struct kdpc *kdpc);
wstdcall void KeFlushQueuedDpcs(void);
wstdcall NTSTATUS KeWaitForSingleObject
	(void *object, KWAIT_REASON reason, KPROCESSOR_MODE waitmode,
	 BOOLEAN alertable, LARGE_INTEGER *timeout);
struct mdl *allocate_init_mdl(void *virt, ULONG length);
void free_mdl(struct mdl *mdl);
wstdcall struct mdl *IoAllocateMdl
	(void *virt, ULONG length, BOOLEAN second_buf, BOOLEAN charge_quota,
	 struct irp *irp);
wstdcall void MmBuildMdlForNonPagedPool(struct mdl *mdl);
wstdcall void IoFreeMdl(struct mdl *mdl);
wfastcall LONG InterlockedDecrement(LONG volatile *val);
wfastcall LONG InterlockedIncrement(LONG volatile *val);
wfastcall struct nt_list *ExInterlockedInsertHeadList
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock);
wfastcall struct nt_list *ExInterlockedInsertTailList
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock);
wfastcall struct nt_list *ExInterlockedRemoveHeadList
	(struct nt_list *head, NT_SPIN_LOCK *lock);
wstdcall NTSTATUS IoCreateDevice
	(struct driver_object *driver, ULONG dev_ext_length,
	 struct unicode_string *dev_name, DEVICE_TYPE dev_type,
	 ULONG dev_chars, BOOLEAN exclusive, struct device_object **dev_obj);
wstdcall NTSTATUS IoCreateSymbolicLink
	(struct unicode_string *link, struct unicode_string *dev_name);
wstdcall void IoDeleteDevice(struct device_object *dev);
wstdcall void IoDetachDevice(struct device_object *topdev);
wstdcall struct device_object *IoGetAttachedDevice(struct device_object *dev);
wstdcall struct device_object *IoGetAttachedDeviceReference
	(struct device_object *dev);
wstdcall NTSTATUS IoAllocateDriverObjectExtension
	(struct driver_object *drv_obj, void *client_id, ULONG extlen,
	 void **ext);
wstdcall void *IoGetDriverObjectExtension
	(struct driver_object *drv, void *client_id);
wstdcall struct device_object *IoAttachDeviceToDeviceStack
	(struct device_object *src, struct device_object *dst);
wstdcall void KeInitializeEvent
	(struct nt_event *nt_event, enum event_type type, BOOLEAN state);
void free_custom_extensions(struct driver_extension *drv_obj_ext);
wstdcall struct irp *IoAllocateIrp(char stack_count, BOOLEAN charge_quota);
wstdcall void IoFreeIrp(struct irp *irp);
wstdcall BOOLEAN IoCancelIrp(struct irp *irp);
wfastcall NTSTATUS IofCallDriver
	(struct device_object *dev_obj, struct irp *irp);
wstdcall struct irp *IoBuildSynchronousFsdRequest
	(ULONG major_func, struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset, struct nt_event *event,
	 struct io_status_block *status);
wstdcall struct irp *IoBuildAsynchronousFsdRequest
	(ULONG major_func,struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset, struct io_status_block *status);
wstdcall NTSTATUS PoCallDriver(struct device_object *dev_obj, struct irp *irp);

wstdcall NTSTATUS IoPassIrpDown
	(struct device_object *dev_obj, struct irp *irp);
wstdcall NTSTATUS IoSyncForwardIrp
	(struct device_object *dev_obj, struct irp *irp);
wstdcall NTSTATUS IoAsyncForwardIrp
	(struct device_object *dev_obj, struct irp *irp);
wstdcall NTSTATUS IoInvalidDeviceRequest
	(struct device_object *dev_obj, struct irp *irp);

struct nt_thread *get_current_nt_thread(void);
u64 ticks_1601(void);

int schedule_ntos_work_item(NTOS_WORK_FUNC func, void *arg1, void *arg2);

wstdcall KIRQL KeGetCurrentIrql(void);
wstdcall void KeInitializeSpinLock(NT_SPIN_LOCK *lock);
wstdcall void KeAcquireSpinLock(NT_SPIN_LOCK *lock, KIRQL *irql);
wstdcall void KeReleaseSpinLock(NT_SPIN_LOCK *lock, KIRQL oldirql);
wstdcall KIRQL KeAcquireSpinLockRaiseToDpc(NT_SPIN_LOCK *lock);

wstdcall void IoAcquireCancelSpinLock(KIRQL *irql);
wstdcall void IoReleaseCancelSpinLock(KIRQL irql);

wfastcall KIRQL KfRaiseIrql(KIRQL newirql);
wfastcall void KfLowerIrql(KIRQL oldirql);
wfastcall KIRQL KfAcquireSpinLock(NT_SPIN_LOCK *lock);
wfastcall void KfReleaseSpinLock(NT_SPIN_LOCK *lock, KIRQL oldirql);
wfastcall void IofCompleteRequest(struct irp *irp, CHAR prio_boost);
wfastcall void KefReleaseSpinLockFromDpcLevel(NT_SPIN_LOCK *lock);
wstdcall void RtlCopyMemory(void *dst, const void *src, SIZE_T length);
wstdcall NTSTATUS RtlUnicodeStringToAnsiString
	(struct ansi_string *dst, const struct unicode_string *src, BOOLEAN dup);
wstdcall NTSTATUS RtlAnsiStringToUnicodeString
	(struct unicode_string *dst, const struct ansi_string *src, BOOLEAN dup);
wstdcall void RtlInitAnsiString(struct ansi_string *dst, const char *src);
wstdcall void RtlInitString(struct ansi_string *dst, const char *src);
wstdcall void RtlInitUnicodeString
	(struct unicode_string *dest, const wchar_t *src);
wstdcall void RtlFreeUnicodeString(struct unicode_string *string);
wstdcall void RtlFreeAnsiString(struct ansi_string *string);
wstdcall LONG RtlCompareUnicodeString
	(const struct unicode_string *s1, const struct unicode_string *s2,
	 BOOLEAN case_insensitive);
wstdcall void RtlCopyUnicodeString
	(struct unicode_string *dst, struct unicode_string *src);
noregparm SIZE_T _win_wcslen(const wchar_t *s);

void wrap_init_timer(struct nt_timer *nt_timer, enum timer_type type,
		     struct kdpc *kdpc, struct ndis_miniport_block *nmb);
BOOLEAN wrap_set_timer(struct nt_timer *nt_timer, unsigned long expires_hz,
		       unsigned long repeat_hz, struct kdpc *kdpc);

wstdcall void KeInitializeTimer(struct nt_timer *nt_timer);
wstdcall void KeInitializeTimerEx
	(struct nt_timer *nt_timer, enum timer_type type);
wstdcall BOOLEAN KeSetTimerEx
	(struct nt_timer *nt_timer, LARGE_INTEGER duetime_ticks, LONG period_ms,
	 struct kdpc *kdpc);
wstdcall BOOLEAN KeSetTimer
	(struct nt_timer *nt_timer, LARGE_INTEGER duetime_ticks,
	 struct kdpc *kdpc);
wstdcall BOOLEAN KeCancelTimer(struct nt_timer *nt_timer);
wstdcall void KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx);

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

wstdcall struct task_struct *KeGetCurrentThread(void);
wstdcall NTSTATUS ObReferenceObjectByHandle
	(void *handle, ACCESS_MASK desired_access, void *obj_type,
	 KPROCESSOR_MODE access_mode, void **object, void *handle_info);
wfastcall LONG ObfReferenceObject(void *object);
wfastcall void ObfDereferenceObject(void *object);

#define ObReferenceObject(object) ObfReferenceObject(object)
#define ObDereferenceObject(object) ObfDereferenceObject(object)

#define MSG(level, fmt, ...)				\
	printk(level "ndiswrapper (%s:%d): " fmt "\n",	\
	       __FUNCTION__, __LINE__ , ## __VA_ARGS__)
#define WARNING(fmt, ...) MSG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) MSG(KERN_ERR, fmt , ## __VA_ARGS__)
#define INFO(fmt, ...) MSG(KERN_INFO, fmt , ## __VA_ARGS__)

#define INFOEXIT(stmt) do { INFO("Exit"); stmt; } while(0)

#define UNIMPL() ERROR("--UNIMPLEMENTED--")

void adjust_user_shared_data_addr(char *driver, unsigned long length);

#define IoCompleteRequest(irp, prio) IofCompleteRequest(irp, prio)
#define IoCallDriver(dev, irp) IofCallDriver(dev, irp)

static inline KIRQL current_irql(void)
{
	if (in_irq() || irqs_disabled())
		return DEVICE_LEVEL;
	if (in_atomic())
		return DISPATCH_LEVEL;
	return PASSIVE_LEVEL;
}

static inline KIRQL raise_irql(KIRQL newirql)
{
	KIRQL irql = current_irql();
	if (irql < DISPATCH_LEVEL && newirql == DISPATCH_LEVEL) {
		local_bh_disable();
		preempt_disable();
	}
	return irql;
}

static inline void lower_irql(KIRQL oldirql)
{
#ifdef DEBUG_IRQL
	KIRQL irql = current_irql();
	if (irql < oldirql)
		ERROR("invalid irql: %d < %d", irql, oldirql);
#endif
//	if (irql == DISPATCH_LEVEL && oldirql < DISPATCH_LEVEL) {
	if (oldirql < DISPATCH_LEVEL) {
		preempt_enable_no_resched();
		local_bh_enable();
	}
}

/* Windows spinlocks are of type ULONG_PTR which is not big enough to
 * store Linux spinlocks; so we implement Windows spinlocks using
 * ULONG_PTR space with our own functions/macros */

/* Windows seems to use 0 for unlocked state of spinlock - if Linux
 * convention of 1 for unlocked state is used, at least prism54 driver
 * crashes */

#define NT_SPIN_LOCK_UNLOCKED 0
#define NT_SPIN_LOCK_LOCKED 1

static inline void  nt_spin_lock_init(volatile NT_SPIN_LOCK *lock)
{
	*lock = NT_SPIN_LOCK_UNLOCKED;
}

#ifdef CONFIG_SMP

static inline void nt_spin_lock(volatile NT_SPIN_LOCK *lock)
{
	__asm__ __volatile__(
		"\n"
		"1:\t"
		"  xchgl %1, %0\n\t"
		"  cmpl %2, %1\n\t"
		"  je 3f\n"
		"2:\t"
		"  rep; nop\n\t"
		"  cmpl %2, %0\n\t"
		"  jne 2b\n\t"
		"  jmp 1b\n"
		"3:\n\t"
		: "=m" (*lock)
		: "r" (NT_SPIN_LOCK_LOCKED), "i" (NT_SPIN_LOCK_UNLOCKED)
		: "memory");
}

static inline void nt_spin_unlock(volatile NT_SPIN_LOCK *lock)
{
	*lock = NT_SPIN_LOCK_UNLOCKED;
}

#else // CONFIG_SMP

#define nt_spin_lock(lock) do { } while (0)

#define nt_spin_unlock(lock)  do { } while (0)

#endif // CONFIG_SMP

/* raise IRQL to given (higher) IRQL if necessary before locking */
static inline KIRQL nt_spin_lock_irql(NT_SPIN_LOCK *lock, KIRQL newirql)
{
	KIRQL oldirql = raise_irql(newirql);
	nt_spin_lock(lock);
	return oldirql;
}

/* lower IRQL to given (lower) IRQL if necessary after unlocking */
static inline void nt_spin_unlock_irql(NT_SPIN_LOCK *lock, KIRQL oldirql)
{
	nt_spin_unlock(lock);
	lower_irql(oldirql);
}

#ifdef CONFIG_PREEMPT_RT
#define save_local_irq(flags) raw_local_irq_save(flags)
#define restore_local_irq(flags) raw_local_irq_restore(flags)
#else
#define save_local_irq(flags) local_irq_save(flags)
#define restore_local_irq(flags) local_irq_restore(flags)
#endif

#define nt_spin_lock_irqsave(lock, flags)				\
do {									\
	save_local_irq(flags);						\
	preempt_disable();						\
	nt_spin_lock(lock);						\
} while (0)

#define nt_spin_unlock_irqrestore(lock, flags)				\
do {									\
	nt_spin_unlock(lock);						\
	restore_local_irq(flags);					\
	preempt_enable();						\
} while (0)

static inline void atomic_inc_size(char *mem, unsigned int size)
{								
	if (size == 1)
		__asm__ __volatile__(				
			LOCK_PREFIX "incb %b0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
	else if (size == 2)
		__asm__ __volatile__(
			LOCK_PREFIX "incw %w0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
	else if (size == 4)
		__asm__ __volatile__(
			LOCK_PREFIX "incl %0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
#ifdef CONFIG_X86_64
	else if (size == 8)
		__asm__ __volatile__(
			LOCK_PREFIX "incq %q0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
#endif
	else
		ERROR("invalid size %d", size);
}

#define atomic_inc(mem) atomic_inc_size((char *)mem, sizeof(*mem))

static inline void atomic_dec_size(char *mem, unsigned int size)
{								
	if (size == 1)
		__asm__ __volatile__(				
			LOCK_PREFIX "decb %b0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
	else if (size == 2)
		__asm__ __volatile__(
			LOCK_PREFIX "decw %w0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
	else if (size == 4)
		__asm__ __volatile__(
			LOCK_PREFIX "decl %0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
#ifdef CONFIG_X86_64
	else if (size == 8)
		__asm__ __volatile__(
			LOCK_PREFIX "decq %q0\n\t"
			: "=m" (*mem)
			: "m" (*mem));
#endif
	else
		ERROR("invalid size %d", size);
}

#define atomic_dec(mem) atomic_dec_size((char *)mem, sizeof(*mem))

#define pre_atomic_add(var, i)					\
({								\
	typeof(var) pre;					\
	__asm__ __volatile__(					\
		LOCK_PREFIX "xadd %0, %1\n\t"			\
		: "=g"(pre), "+m"(var)				\
		: "0"(i)					\
		: "cc");					\
	pre;							\
})

#define post_atomic_add(var, i) (pre_atomic_add(var, i) + i)

static inline ULONG SPAN_PAGES(void *ptr, SIZE_T length)
{
	ULONG n;

	n = ((((ULONG_PTR)ptr) & (PAGE_SIZE - 1)) + length + (PAGE_SIZE - 1))
		>> PAGE_SHIFT;

	return n;
}

#ifdef CONFIG_X86_64
/* it is not clear how nt_slist_header is used to store pointer to
 * slists and depth; here we assume 'align' field is used to store
 * depth and 'region' field is used to store slist pointers */

/* TODO: can these be implemented without using spinlock? */

static inline struct nt_slist *PushEntrySList(nt_slist_header *head,
					      struct nt_slist *entry,
					      NT_SPIN_LOCK *lock)
{
	KIRQL irql = nt_spin_lock_irql(lock, DISPATCH_LEVEL);
	entry->next = head->next;
	head->next = entry;
	head->align++;
	nt_spin_unlock_irql(lock, irql);
	return entry->next;
}

static inline struct nt_slist *PopEntrySList(nt_slist_header *head,
					     NT_SPIN_LOCK *lock)
{
	struct nt_slist *entry;
	KIRQL irql = nt_spin_lock_irql(lock, DISPATCH_LEVEL);
	entry = head->next;
	if (entry) {
		head->next = entry->next;
		head->align--;
	}
	nt_spin_unlock_irql(lock, irql);
	return entry;
}

#else

#ifndef ll_low
#define ll_low(x) *(((u32 *)&(x)) + 0)
#define ll_high(x) *(((u32 *)&(x)) + 1)
#endif

static inline u64 cmpxchg8b(volatile void *ptr, u64 old, u64 new)
{
	u64 prev;

	__asm__ __volatile__(
		"\n"
		LOCK_PREFIX "cmpxchg8b (%0)\n"
		: "+r" (ptr),
		  "=a" (ll_low(prev)), "=d" (ll_high(prev))
		: "a" (ll_low(old)), "d" (ll_high(old)),
		  "b" (ll_low(new)), "c" (ll_high(new))
		: "cc", "memory");
	return prev;
}

/* slist routines below update slist atomically - no need for
 * spinlocks */

static inline struct nt_slist *PushEntrySList(nt_slist_header *head,
					      struct nt_slist *entry,
					      NT_SPIN_LOCK *lock)
{
	nt_slist_header old, new;
	do {
		old.align = head->align;
		entry->next = old.next;
		new.next = entry;
		new.depth = old.depth + 1;
	} while (cmpxchg8b(&head->align, old.align, new.align) != old.align);
	return old.next;
}

static inline struct nt_slist *PopEntrySList(nt_slist_header *head,
					     NT_SPIN_LOCK *lock)
{
	struct nt_slist *entry;
	nt_slist_header old, new;
	do {
		old.align = head->align;
		entry = old.next;
		if (!entry)
			break;
		new.next = entry->next;
		new.depth = old.depth - 1;
	} while (cmpxchg8b(&head->align, old.align, new.align) != old.align);
	return entry;
}

#endif

/* DEBUG macros */

#define DBGTRACE(fmt, ...) do { } while (0)
#define DBGTRACE1(fmt, ...) do { } while (0)
#define DBGTRACE2(fmt, ...) do { } while (0)
#define DBGTRACE3(fmt, ...) do { }  while (0)
#define DBGTRACE4(fmt, ...) do { } while (0)
#define DBGTRACE5(fmt, ...) do { } while (0)
#define DBGTRACE6(fmt, ...) do { } while (0)

/* for a block of code */
#define DBG_BLOCK(level) while (0)

extern int debug;

#if defined DEBUG
#undef DBGTRACE
#define DBGTRACE(level, fmt, ...)				       \
do {								       \
	if (debug >= level)					       \
		printk(KERN_INFO "%s (%s:%d): " fmt "\n", DRIVER_NAME, \
		       __FUNCTION__, __LINE__ , ## __VA_ARGS__);       \
} while (0)
#undef DBG_BLOCK
#define DBG_BLOCK(level) if (debug >= level)
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

#define TRACEENTER1(fmt, ...) DBGTRACE1("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER2(fmt, ...) DBGTRACE2("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER3(fmt, ...) DBGTRACE3("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER4(fmt, ...) DBGTRACE4("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER5(fmt, ...) DBGTRACE5("Enter " fmt , ## __VA_ARGS__)
#define TRACEENTER6(fmt, ...) DBGTRACE6("Enter " fmt , ## __VA_ARGS__)

#define TRACEEXIT1(stmt) do { DBGTRACE1("Exit"); stmt; } while(0)
#define TRACEEXIT2(stmt) do { DBGTRACE2("Exit"); stmt; } while(0)
#define TRACEEXIT3(stmt) do { DBGTRACE3("Exit"); stmt; } while(0)
#define TRACEEXIT4(stmt) do { DBGTRACE4("Exit"); stmt; } while(0)
#define TRACEEXIT5(stmt) do { DBGTRACE5("Exit"); stmt; } while(0)
#define TRACEEXIT6(stmt) do { DBGTRACE6("Exit"); stmt; } while(0)

#if defined(USB_DEBUG)
#define USBTRACE DBGTRACE1
#define USBENTER TRACEENTER1
#define USBEXIT TRACEEXIT1
#else
#define USBTRACE(fmt, ...)
#define USBENTER(fmt, ...)
#define USBEXIT(stmt) stmt
#endif

#if defined(EVENT_DEBUG)
#define EVENTTRACE DBGTRACE1
#define EVENTENTER TRACEENTER1
#define EVENTEXIT TRACEEXIT1
#else
#define EVENTTRACE(fmt, ...)
#define EVENTENTER(fmt, ...)
#define EVENTEXIT(stmt) stmt
#endif

#if defined(IO_DEBUG)
#define IOTRACE DBGTRACE1
#define IOENTER TRACEENTER1
#define IOEXIT TRACEEXIT1
#else
#define IOTRACE(fmt, ...)
#define IOENTER(fmt, ...)
#define IOEXIT(stmt) stmt
#endif

#if defined(WORK_DEBUG)
#define WORKTRACE DBGTRACE1
#define WORKENTER TRACEENTER1
#define WORKEXIT TRACEEXIT1
#else
#define WORKTRACE(fmt, ...)
#define WORKENTER(fmt, ...)
#define WORKEXIT(stmt) stmt
#endif

#if defined DEBUG
#define assert(expr)							\
do {									\
	if (!(expr))							\
		ERROR("assertion '%s' failed", #expr);			\
} while (0)
#else
#define assert(expr) do { } while (0)
#endif

#if defined(IO_DEBUG)
#define DUMP_IRP(irp)							\
do {									\
	struct io_stack_location *irp_sl;				\
	irp_sl = IoGetCurrentIrpStackLocation(irp);			\
	IOTRACE("irp: %p, stack size: %d, cl: %d, sl: %p, dev_obj: %p, " \
		"mj_fn: %d, minor_fn: %d, nt_urb: %p, event: %p",	\
		irp, irp->stack_count, (irp)->current_location,		\
		irp_sl, irp_sl->dev_obj, irp_sl->major_fn,		\
		irp_sl->minor_fn, URB_FROM_IRP(irp),			\
		(irp)->user_event);					\
} while (0)
#else
#define DUMP_IRP(irp) do { } while (0)
#endif

#define sleep_hz(n)					\
do {							\
	set_current_state(TASK_INTERRUPTIBLE);		\
	schedule_timeout(n);				\
} while (0)

#endif // _NTOSKERNEL_H_
