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
#include <asm/mman.h>
#include <asm/atomic.h>

#include <linux/version.h>

#define STDCALL __attribute__((__stdcall__, regparm(0)))
#define NOREGPARM __attribute__((regparm(0)))
#define packed __attribute__((packed))
#define _FASTCALL __attribute__((__stdcall__)) __attribute__((regparm (3)))

#define MAX_STR_LEN 512

#define TRUE 1
#define FALSE 0

#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2

#define STATUS_SUCCESS                  0
#define STATUS_ALERTED                  0x00000101
#define STATUS_TIMEOUT                  0x00000102
#define STATUS_PENDING                  0x00000103
#define STATUS_FAILURE                  0xC0000001
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define STATUS_BUFFER_TOO_SMALL         0xC0000023
#define STATUS_RESOURCES                0xC000009A
#define STATUS_NOT_SUPPORTED            0xC00000BB
#define STATUS_INVALID_PARAMETER_2      0xC00000F0
#define STATUS_CANCELLED                0xC0000120

#define IS_PENDING                      0x01
#define CALL_ON_CANCEL                  0x20
#define CALL_ON_SUCCESS                 0x40
#define CALL_ON_ERROR                   0x80


struct slist_entry
{
	struct slist_entry  *next;
};

union slist_head {
	unsigned long long align;
	struct packed
	{
		struct slist_entry  *next;
		unsigned short depth;
		unsigned short sequence;
	} list;
};

typedef unsigned char KIRQL;
struct packed wrap_spinlock
{
	spinlock_t spinlock;
	unsigned short magic;
	KIRQL irql;
};

/* typedef unsigned long *KSPIN_LOCK; */
typedef struct wrap_spinlock *KSPIN_LOCK;
typedef char KPROCESSOR_MODE;
typedef unsigned char BOOLEAN;

struct list_entry
{
	struct list_entry *fwd_link;
	struct list_entry *bwd_link;
};

struct packed dispatch_header
{
	unsigned char type;
	unsigned char absolute;
	unsigned char size;
	unsigned char inserted;
	long signal_state;
	struct list_entry wait_list_head;
};

struct ktimer;
struct kdpc;

#define WRAPPER_TIMER_MAGIC 47697249
struct wrapper_timer
{
	struct list_head list;
	struct timer_list timer;
#ifdef DEBUG_TIMER
	unsigned long wrapper_timer_magic;
#endif
	long repeat;
	int active;
	struct ktimer *ktimer;
	struct kdpc *kdpc;
	spinlock_t lock;
};

struct packed kdpc
{
	short type;
	unsigned char number;
	unsigned char importance;
	struct list_entry dpc_list_entry;

	void *func;
	void *ctx;
	void *arg1;
	void *arg2;
	unsigned long *lock;
};

enum pool_type
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
};

struct irp;

struct packed device_object
{
	short type;
	unsigned short size;
	long fill1;
	void *drv_obj;
	struct device_object *next_dev;
	void *fill2;
	struct irp *current_irp;
	void *fill4;
	unsigned long flags;
	unsigned long characteristics;
	void *fill5;
	void *dev_ext;
	unsigned long dev_type;
	char stack_size;
	char fill6[3+10*4];
	unsigned long align_req;
	char fill7[100]; /* more than required */

	/* ndiswrapper-specific data */
	union {
		struct usb_device *usb;
	} device;
	void *handle;
};

struct io_status_block {
	long status;
	unsigned long status_info;
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
			unsigned long output_buf_len;
			unsigned long input_buf_len; /*align to pointer size*/
			unsigned long code; /*align to pointer size*/
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
	unsigned long (*completion_handler)(struct device_object *,
	                                    struct irp *, void *) STDCALL;
	void *handler_arg;
};

enum irp_work_type {
	IRP_WORK_NONE,
	IRP_WORK_COMPLETE,
	IRP_WORK_CANCEL,
};

struct packed irp {
	short type;
	unsigned short size;
	void *mdl;
	unsigned long flags;
	union {
		struct irp *master_irp;
		void *sys_buf;
	} associated_irp;

	void *fill1[2];

	struct io_status_block io_status;
	char requestor_mode;
	unsigned char pending_returned;
	char stack_size;
	char stack_pos;
	unsigned char cancel;
	unsigned char cancel_irql;

	char fill2[2];

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

enum nt_obj_type
{
	NT_OBJ_EVENT,
	NT_OBJ_MUTEX,
	NT_OBJ_THREAD,
	NT_OBJ_TIMER,
};

struct ktimer
{
	struct dispatch_header dispatch_header;
	u64 due_time;
	struct list_entry timer_list;
	/* the space for kdpc is used for wrapper timer */
	/* struct kdpc *kdpc; */
	struct wrapper_timer *wrapper_timer;
	long period;
};

struct kmutex
{
	struct dispatch_header dispatch_header;
	/* struct list_entry list_entry */
	unsigned int count;
	unsigned int dummy;
	void *owner_thread;
	BOOLEAN abandoned;
	unsigned char apc_disable;
};

#define NOTIFICATION_TIMER 1

struct kevent
{
	struct dispatch_header header;
};

#define NOTIFICATION_EVENT	0
#define SYNCHRONIZATION_EVENT	1

typedef STDCALL void *LOOKASIDE_ALLOC_FUNC(enum pool_type pool_type,
					   size_t size, unsigned long tag);
typedef STDCALL void LOOKASIDE_FREE_FUNC(void *);

struct packed npaged_lookaside_list {
	union slist_head head;
	unsigned short depth;
	unsigned short maxdepth;
	unsigned long totalallocs;
	unsigned long allocmisses;
	unsigned long totalfrees;
	unsigned long freemisses;
	enum pool_type pool_type;
	unsigned long tag;
	unsigned long size;
	LOOKASIDE_ALLOC_FUNC *alloc_func;
	LOOKASIDE_FREE_FUNC *free_func;
	struct list_entry listent;
	unsigned long lasttotallocs;
	unsigned long lastallocmisses;
	unsigned long pad[2];
	KSPIN_LOCK obsolete;
};

enum device_prop
{
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

void wrapper_init_timer(struct ktimer *ktimer, void *handle);
int wrapper_set_timer(struct wrapper_timer *wrapper_timer,
                      unsigned long expires, unsigned long repeat,
                      struct kdpc *kdpc);
void wrapper_cancel_timer(struct wrapper_timer *wrapper_timer, char *canceled);
STDCALL void KeInitializeEvent(struct kevent *kevent, int type, int state);
STDCALL long KeSetEvent(struct kevent *kevent, int incr, int wait);
STDCALL long KeResetEvent(struct kevent *kevent);
STDCALL unsigned int KeWaitForSingleObject(void *object, unsigned int reason,
					   unsigned int waitmode,
					   unsigned short alertable,
					   s64 *timeout);
u64 ticks_1601(void);

STDCALL KIRQL KeGetCurrentIrql(void);
STDCALL void KeInitializeSpinLock(KSPIN_LOCK *lock);
_FASTCALL KIRQL KfAcquireSpinLock(int dummy1, int dummy2, KSPIN_LOCK *lock);
_FASTCALL void KfReleaseSpinLock(int dummy, KIRQL oldirql, KSPIN_LOCK *lock);
STDCALL void KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *irql);
STDCALL void KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL oldirql);
_FASTCALL KIRQL KfRaiseIrql(int dummy1, int dummy2, KIRQL newirql);
_FASTCALL void KfLowerIrql(int dummy1, int dummy2, KIRQL oldirql);
_FASTCALL void IofCompleteRequest(int dummy, char prio_boost, struct irp *irp);

#define WRAPPER_SPIN_LOCK_MAGIC 137

#define wrap_spin_lock_init(lock) do {				\
		spin_lock_init(&((lock)->spinlock));		\
		(lock)->magic = WRAPPER_SPIN_LOCK_MAGIC;	\
	} while (0)
#define wrap_spin_lock(lock)  do {					\
		(lock)->irql = KfRaiseIrql(0, 0, DISPATCH_LEVEL);	\
		spin_lock(&((lock)->spinlock));				\
	} while (0)
#define wrap_spin_unlock(lock) do {			\
		spin_unlock(&((lock)->spinlock));	\
		KfLowerIrql(0, 0, (lock)->irql);	\
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

#define raise_irql(irql) KfRaiseIrql(0, 0, irql)
#define lower_irql(irql) KfLowerIrql(0, 0, irql)

#endif // _NTOSKERNEL_H_
