/*
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

#include "ndiswrapper.h"

#define DEBUG_IRQL 1

#ifdef CONFIG_X86_64
typedef uint64_t ULONG_PTR;
#define STDCALL
#define _FASTCALL
#define FASTCALL_DECL_1(decl1) decl1
#define FASTCALL_DECL_2(decl1,decl2) decl1, decl2
#define FASTCALL_DECL_3(decl1,decl2,decl3) decl1, decl2, decl3
#define FASTCALL_ARGS_1(arg1) arg1
#define FASTCALL_ARGS_2(arg1,arg2) arg1, arg2
#define FASTCALL_ARGS_3(arg1,arg2,arg3) arg1, arg2, arg3
#else 
typedef uint32_t ULONG_PTR;
#define STDCALL __attribute__((__stdcall__, regparm(0)))
#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))
#define FASTCALL_DECL_1(decl1) int _dummy1_, int _dummy2_, decl1
#define FASTCALL_DECL_2(decl1,decl2) int _dummy1_, decl2, decl1
#define FASTCALL_DECL_3(decl1,decl2,decl3) int _dummy1_, decl2, decl1, decl3
#define FASTCALL_ARGS_1(arg1) 0, 0, arg1
#define FASTCALL_ARGS_2(arg1,arg2) 0, arg2, arg1
#define FASTCALL_ARGS_3(arg1,arg2,arg3) 0, arg2, arg1, arg3
#endif

#define NOREGPARM __attribute__((regparm(0)))
#define packed __attribute__((packed))

#define MAX_STR_LEN 512

#define TRUE 1
#define FALSE 0

#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

#define STATUS_WAIT_0			0
#define STATUS_SUCCESS                  0
#define STATUS_ALERTED                  0x00000101
#define STATUS_TIMEOUT                  0x00000102
#define STATUS_PENDING                  0x00000103
#define STATUS_FAILURE                  0xC0000001
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define STATUS_BUFFER_TOO_SMALL         0xC0000023
#define STATUS_RESOURCES                0xC000009A
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_INVALID_PARAMETER        0xC000000D
#define STATUS_INVALID_PARAMETER_2      0xC00000F0
#define STATUS_CANCELLED                0xC0000120

#define IS_PENDING                      0x01
#define CALL_ON_CANCEL                  0x20
#define CALL_ON_SUCCESS                 0x40
#define CALL_ON_ERROR                   0x80

typedef int8_t		CHAR;
typedef uint8_t		UCHAR;
typedef uint8_t		BOOLEAN;
typedef uint8_t		BYTE;
typedef uint8_t		*LPBYTE;
typedef int16_t		SHORT;
typedef uint16_t	USHORT;
typedef uint16_t	WORD;
typedef uint32_t	DWORD;
typedef int32_t		LONG;
typedef int32_t		INT;
typedef uint32_t	ULONG;
typedef uint32_t	UINT;
typedef uint64_t	ULONGLONG;
typedef int64_t		LARGE_INTEGER;

typedef ULONG_PTR	SIZE_T;
typedef LONG KPRIORITY;
typedef INT NT_STATUS;
typedef LARGE_INTEGER	PHYSICAL_ADDRESS;
typedef ULONG_PTR	KAFFINITY;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
#include <linux/kthread.h>
#endif

#if !defined(CONFIG_USB) && defined(CONFIG_USB_MODULE)
#define CONFIG_USB 1
#endif

#define DRV_NAME "ndiswrapper"

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
			   GFP_KERNEL | __GFP_REPEAT)
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

#define WRAP_ALLOC_URB(a, b)  usb_alloc_urb(a)
#define WRAP_SUBMIT_URB(a, b) usb_submit_urb(a)

#else // LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define WRAP_ALLOC_URB(a, b)  usb_alloc_urb(a, b)
#define WRAP_SUBMIT_URB(a, b) usb_submit_urb(a, b)

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#ifdef CONFIG_SOFTWARE_SUSPEND2
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,0,c)
#else
#define KTHREAD_RUN(a,b,c) kthread_run(a,b,c)
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

#define WRAP_EXPORT_SYMBOL(f) {#f, (WRAP_EXPORT_FUNC)f}
/* map name s to function f - if f is different from s */
#define WRAP_EXPORT_MAP(s,f)
#define WRAP_EXPORT(x) x

struct wrap_alloc {
	struct list_head list;
	void *ptr;
};

typedef unsigned char mac_address[ETH_ALEN];

struct pe_image {
	char name[MAX_DRIVER_NAME_LEN];
	void *entry;
	void *image;
	int size;
	int type;
};

struct ustring {
	USHORT len;
	USHORT buflen;
	char *buf;
};

struct slist_entry {
	struct slist_entry  *next;
};

union slist_head {
	ULONGLONG align;
	struct packed {
		struct slist_entry  *next;
		USHORT depth;
		USHORT sequence;
	} list;
};

typedef unsigned char KIRQL;

/* KSPIN_LOCK is typedef to ULONG_PTR, where ULONG_PTR is 32-bit
 * 32-bit platforms, 64-bit on 64 bit platforms; it is NOT pointer to
 * unsigned long  */
/* spinlock_t is 32-bits, provided CONFIG_DEBUG_SPINLOCK is disabled;
 * so for x86 32-bits, we can safely typedef KSPIN_LOCK to
 * spinlock_t */

#ifdef CONFIG_DEBUG_SPINLOCK
struct wrap_spinlock {
	spinlock_t spinlock;
	KIRQL use_bh;
};
typedef struct wrap_spinlock *KSPIN_LOCK;
#define WRAP_SPINLOCK(lock) &((lock)->spinlock)
#define K_SPINLOCK(lock) &((*lock)->spinlock)

#else

typedef union {
	spinlock_t spinlock;
	ULONG_PTR ntoslock;
} KSPIN_LOCK;
struct wrap_spinlock {
	KSPIN_LOCK klock;
	KIRQL use_bh;
};

#define WRAP_SPINLOCK(lock) &((lock)->klock.spinlock)
#define K_SPINLOCK(lock) &(lock)->spinlock
#endif

typedef CHAR KPROCESSOR_MODE;

struct list_entry {
	struct list_entry *fwd_link;
	struct list_entry *bwd_link;
};

struct packed dispatch_header {
	UCHAR type;
	UCHAR absolute;
	UCHAR size;
	UCHAR inserted;
	LONG signal_state;
	struct list_head wait_list_head;
};

struct kevent {
	struct dispatch_header header;
};

struct ktimer;
struct kdpc;

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

struct packed kdpc {
	SHORT type;
	UCHAR number;
	UCHAR importance;
	struct list_entry dpc_list_entry;

	void *func;
	void *ctx;
	void *arg1;
	void *arg2;
	KSPIN_LOCK lock;
};

enum pool_type {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
};

enum memory_caching_type {
	MM_NON_CACHED = FALSE,
	MM_CACHED = TRUE,
	MM_WRITE_COMBINED = 2,
	MM_HARDWARE_COHERENT_CACHED,
	MM_NON_CACHED_UNORDERED,
	MM_USWC_CACHED,
	MM_MAXIMUM_CACHE_TYPE
};

struct mdl {
	struct mdl* next;
	SHORT size;
	SHORT mdlflags;
	void *process;
	void *mappedsystemva;
	void *startva;
	ULONG bytecount;
	ULONG byteoffset;
};


struct irp;

struct device_queue_entry {
	struct list_entry list_entry;
	ULONG sort_key;
	BOOLEAN inserted;
};

struct wait_ctx_block {
	struct device_queue_entry wait_queue_entry;
	void *dev_routine;
	void *dev_ctx;
	ULONG map_reg_count;
	void *current_irp;
	void *buffer_chaining_dpc;
};

struct kdevice_queue {
	USHORT type;
	USHORT size;
	struct list_entry devlist_head;
	KSPIN_LOCK lock;
	BOOLEAN busy;
};

struct packed device_object {
	SHORT type;
	USHORT size;
	LONG ref_count;
	void *drv_obj;
	struct device_object *next_dev;
	void *attached_dev;
	struct irp *current_irp;
	void *io_timer;
	ULONG flags;
	ULONG characteristics;
	void *vpb;
	void *dev_ext;
	BYTE stack_size;
	union {
		struct list_entry list_entry;
		struct wait_ctx_block wcb;
	} queue;
	ULONG align_req;
	struct kdevice_queue dev_queue;
	struct kdpc dpc;
	UINT active_threads;
	void *security_desc;
	struct kevent dev_lock;
	USHORT sector_size;
	USHORT spare;
	void *dev_obj_ext;
	void *reserved;

	/* ndiswrapper-specific data */
	union {
		struct usb_device *usb;
	} device;
	void *handle;
};

struct io_status_block {
	NT_STATUS status;
	ULONG status_info;
};

#define IRP_MJ_DEVICE_CONTROL           0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0F

struct packed io_stack_location {
	char major_fn;
	char minor_fn;
	char flags;
	char control;
	union {
		struct {
			ULONG output_buf_len;
			ULONG input_buf_len; /*align to pointer size*/
			ULONG code; /*align to pointer size*/
			void *type3_input_buf;
		} ioctl;
		struct {
			void *arg1;
			void *arg2;
			void *arg3;
			void *arg4;
		} generic;
	} params;
	struct device_object *dev_obj;
	void *fill;
	ULONG (*completion_handler)(struct device_object *,
				    struct irp *, void *) STDCALL;
	void *handler_arg;
};

enum irp_work_type {
	IRP_WORK_NONE,
	IRP_WORK_COMPLETE,
	IRP_WORK_CANCEL,
};

struct packed irp {
	SHORT type;
	USHORT size;
	void *mdl;
	ULONG flags;
	union {
		struct irp *master_irp;
		void *sys_buf;
	} associated_irp;

	void *fill1[2];

	struct io_status_block io_status;
	CHAR requestor_mode;
	UCHAR pending_returned;
	CHAR stack_size;
	CHAR stack_pos;
	UCHAR cancel;
	UCHAR cancel_irql;

	CHAR fill2[2];

	struct io_status_block *user_status;
	struct kevent *user_event;

	void *fill3[2];

	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;
	void *user_buf;
	void *driver_context[4];
	void *thread;

	void *fill4;

	struct list_entry list_entry;
	struct io_stack_location *current_stack_location;

	void *fill5[3];

	/* ndiswrapper extension */
	enum irp_work_type irp_work_type;
	struct list_head cancel_list_entry;
};

enum nt_obj_type {
	NT_OBJ_EVENT,
	NT_OBJ_MUTEX,
	NT_OBJ_THREAD,
	NT_OBJ_TIMER,
};

struct ktimer {
	struct dispatch_header dispatch_header;
	ULONGLONG due_time;
	struct list_entry timer_list;
	/* the space for kdpc is used for wrapper timer */
	/* struct kdpc *kdpc; */
	struct wrapper_timer *wrapper_timer;
	LONG period;
};

struct kmutex {
	struct dispatch_header dispatch_header;
	union {
		struct list_entry list_entry;
		UINT count;
	} u;
	void *owner_thread;
	BOOLEAN abandoned;
	BOOLEAN apc_disable;
};

enum wait_type {
	WAIT_ALL,
	WAIT_ANY
};

struct wait_block {
	struct list_entry list_entry;
	void *thread;
	struct dispatch_header *object;
	struct wait_block *next;
	USHORT wait_key;
	USHORT wait_type;
};

#define WAIT_ALL 0
#define WAIT_ANY 1

#define THREAD_WAIT_OBJECTS 3
#define MAX_WAIT_OBJECTS 64

#define NOTIFICATION_TIMER 1

enum ntos_event_type {
	NOTIFICATION_EVENT,
	SYNCHRONIZATION_EVENT
};

typedef enum ntos_event_type KEVENT_TYPE;

enum ntos_wait_reason {
	WAIT_REASON_EXECUTIVE,
	WAIT_REASON_FREEPAGE,
	WAIT_REASON_PAGEIN,
	WAIT_REASON_POOLALLOCATION,
	WAIT_REASON_DELAYEXECUTION,
	WAIT_REASON_SUSPENDED,
	WAIT_REASON_USERREQUEST,
	WAIT_REASON_WREXECUTIVE,
	WAIT_REASON_WRFREEPAGE,
	WAIT_REASON_WRPAGEIN,
	WAIT_REASON_WRPOOLALLOCATION,
	WAIT_REASON_WRDELAYEXECUTION,
	WAIT_REASON_WRSUSPENDED,
	WAIT_REASON_WRUSERREQUEST,
	WAIT_REASON_WREVENTPAIR,
	WAIT_REASON_WRQUEUE,
	WAIT_REASON_WRLPCRECEIVE,
	WAIT_REASON_WRLPCREPLY,
	WAIT_REASON_WRVIRTUALMEMORY,
	WAIT_REASON_WRPAGEOUT,
	WAIT_REASON_WRRENDEZVOUS,
	WAIT_REASON_SPARE2,
	WAIT_REASON_SPARE3,
	WAIT_REASON_SPARE4,
	WAIT_REASON_SPARE5,
	WAIT_REASON_SPARE6,
	WAIT_REASON_WRKERNEL,
	WAIT_REASON_MAXIMUM
};

typedef enum ntos_wait_reason KWAIT_REASON;

#define LOW_PRIORITY 		1
#define LOW_REALTIME_PRIORITY	16
#define HIGH_PRIORITY		32
#define MAXIMUM_PRIORITY	32

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
					   SIZE_T size, ULONG tag);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct packed npaged_lookaside_list {
	union slist_head head;
	USHORT depth;
	USHORT maxdepth;
	ULONG totalallocs;
	ULONG allocmisses;
	ULONG totalfrees;
	ULONG freemisses;
	enum pool_type pool_type;
	ULONG tag;
	ULONG size;
	LOOKASIDE_ALLOC_FUNC *alloc_func;
	LOOKASIDE_FREE_FUNC *free_func;
	struct list_entry listent;
	ULONG lasttotallocs;
	ULONG lastallocmisses;
	ULONG pad[2];
	KSPIN_LOCK obsolete;
};

enum device_registry_property {
	DEVPROP_DEVICE_DESCRIPTION,
	DEVPROP_HARDWARE_ID,
	DEVPROP_COMPATIBLE_IDS,
	DEVPROP_BOOTCONF,
	DEVPROP_BOOTCONF_TRANSLATED,
	DEVPROP_CLASS_NAME,
	DEVPROP_CLASS_GUID,
	DEVPROP_DRIVER_KEYNAME,
	DEVPROP_MANUFACTURER,
	DEVPROP_FRIENDLYNAME,
	DEVPROP_LOCATION_INFO,
	DEVPROP_PHYSDEV_NAME,
	DEVPROP_BUSTYPE_GUID,
	DEVPROP_LEGACY_BUSTYPE,
	DEVPROP_BUS_NUMBER,
	DEVPROP_ENUMERATOR_NAME,
	DEVPROP_ADDRESS,
	DEVPROP_UINUMBER,
	DEVPROP_INSTALL_STATE,
	DEVPROP_REMOVAL_POLICY,
};

enum trace_information_class {
	TRACE_ID_CLASS,
	TRACE_HANDLE_CLASS,
	TRACE_ENABLE_FLAGS_CLASS,
	TRACE_ENABLE_LEVEL_CLASS,
	GLOBAL_LOGGER_HANDLE_CLASS,
	EVENT_LOGGER_HANDLE_CLASS,
	ALL_LOGGER_HANDLES_CLASS,
	TRACE_HANDLE_BY_NAME_CLASS
};

extern struct wrap_spinlock atomic_lock;
extern struct wrap_spinlock cancel_lock;

#define WRAPPER_SPIN_LOCK_MAGIC 137

void *wrap_kmalloc(size_t size, int flags);
void wrap_kfree(void *ptr);
void wrap_kfree_all(void);

void wrapper_init_timer(struct ktimer *ktimer, void *handle);
int wrapper_set_timer(struct wrapper_timer *wrapper_timer,
                      unsigned long expires, unsigned long repeat,
                      struct kdpc *kdpc);
void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer, char *canceled);
STDCALL void KeInitializeEvent(struct kevent *kevent,
			       KEVENT_TYPE type, BOOLEAN state);
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

static inline ULONG SPAN_PAGES(ULONG_PTR ptr, ULONG length)
{
	ULONG_PTR start, end, n;

	start = (ptr & PAGE_MASK);
	end = (ptr + length + PAGE_SIZE - 1) & PAGE_MASK;
	n = (end - start) / PAGE_SIZE;
	return (ULONG)n;
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
#define ASSERT(expr)						\
	if (!(expr)) {						\
		ERROR("Assertion failed! %s\n", (#expr));	\
	}
#else
#define ASSERT(expr)
#endif

#endif // _NTOSKERNEL_H_
