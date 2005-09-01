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

#include "ntoskernel.h"
#include "ndis.h"
#include "usb.h"

/* macros for (temporarily) debugging SIS USB driver, whose thread
 * keeps going back to uninterruptible wait */
#if 0
#define DBGINFO(fmt, ...) MSG(KERN_INFO, fmt , ## __VA_ARGS__)
#define DBGINFOEXIT(stmt) do { DBGINFO("Exit"); stmt; } while(0)
#else
#define DBGINFO DBGTRACE4
#define DBGINFOEXIT TRACEEXIT4
#endif

/* MDLs describe a range of virtual address with an array of physical
 * pages right after the header. For different ranges of virtual
 * addresses, the number of entries of physical pages may be different
 * (depending on number of entries required). If we want to allocate
 * MDLs from a pool, the size has to be constant. So we assume that
 * maximum range used by a driver is CACHE_MDL_PAGES; if a driver
 * requests an MDL for a bigger region, we allocate it with kmalloc;
 * otherwise, we allocate from the pool */
#define CACHE_MDL_PAGES 2
#define CACHE_MDL_SIZE (sizeof(struct mdl) + (sizeof(ULONG) * CACHE_MDL_PAGES))
struct wrap_mdl {
	struct nt_list list;
	char mdl[CACHE_MDL_SIZE];
};

struct bus_driver {
	struct nt_list list;
	char name[MAX_DRIVER_NAME_LEN];
	struct driver_object *drv_obj;
};

/* everything here is for all drivers/devices - not per driver/device */
static KSPIN_LOCK kevent_lock;
KSPIN_LOCK ntoskernel_lock;
static kmem_cache_t *mdl_cache;
static struct nt_list wrap_mdl_list;

struct work_struct kdpc_work;
static struct nt_list kdpc_list;
static KSPIN_LOCK kdpc_list_lock;
static void kdpc_worker(void *data);

static struct nt_list callback_objects;

struct nt_list object_list;

static struct nt_list bus_driver_list;
static struct driver_object pci_bus_driver;
static struct driver_object usb_bus_driver;
static void del_bus_drivers(void);

struct work_struct io_work;
struct nt_list io_workitem_list;
KSPIN_LOCK io_workitem_list_lock;
void io_worker(void *data);

KSPIN_LOCK irp_cancel_lock;

/* wrap_epoch is when ntoskernel gets initialized */
static u64 wrap_ticks_to_epoch;
static typeof(jiffies) wrap_epoch;

extern struct nt_list ndis_drivers;
extern struct nt_list ndis_work_list;
extern KSPIN_LOCK ndis_work_list_lock;

static int add_bus_driver(struct driver_object *drv_obj, const char *name);

WRAP_EXPORT_MAP("KeTickCount", &jiffies);

int ntoskernel_init(void)
{
	struct timeval now;

	kspin_lock_init(&kevent_lock);
	kspin_lock_init(&ntoskernel_lock);
	kspin_lock_init(&io_workitem_list_lock);
	kspin_lock_init(&kdpc_list_lock);
	kspin_lock_init(&irp_cancel_lock);
	InitializeListHead(&wrap_mdl_list);
	InitializeListHead(&kdpc_list);
	InitializeListHead(&callback_objects);
	InitializeListHead(&bus_driver_list);
	InitializeListHead(&object_list);
	InitializeListHead(&io_workitem_list);
	INIT_WORK(&kdpc_work, kdpc_worker, NULL);
	INIT_WORK(&io_work, io_worker, NULL);

	/* compute ticks since 1601 into wrap_ticks_to_epoch */
	do_gettimeofday(&now);
	wrap_epoch = jiffies;
	wrap_ticks_to_epoch = (u64)now.tv_sec * TICKSPERSEC;
	wrap_ticks_to_epoch += now.tv_usec * 10 + TICKS_1601_TO_1970;

	if (add_bus_driver(&pci_bus_driver, "PCI") ||
	    add_bus_driver(&usb_bus_driver, "USB")) {
		ntoskernel_exit();
		return -ENOMEM;
	}
	mdl_cache = kmem_cache_create("ndis_mdl", sizeof(struct wrap_mdl),
				      0, 0, NULL, NULL);
	if (!mdl_cache) {
		ERROR("couldn't allocate MDL cache");
		ntoskernel_exit();
		return -ENOMEM;
	}
	return 0;
}

void ntoskernel_exit(void)
{
	struct nt_list *cur;
	KIRQL irql;

	KeFlushQueuedDpcs();
	if (mdl_cache) {
		irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		if (!IsListEmpty(&wrap_mdl_list)) {
			ERROR("Windows driver didn't free all MDLs; "
			      "freeing them now");
			while ((cur = RemoveHeadList(&wrap_mdl_list))) {
				struct wrap_mdl *p;
				struct mdl *mdl;
				p = container_of(cur, struct wrap_mdl, list);
				mdl = (struct mdl *)p->mdl;
				if (mdl->flags & MDL_CACHE_ALLOCATED)
					kmem_cache_free(mdl_cache, p);
				else
					kfree(p);
			}
		}
		kspin_unlock_irql(&ntoskernel_lock, irql);
		kmem_cache_destroy(mdl_cache);
		mdl_cache = NULL;
	}
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((cur = RemoveHeadList(&callback_objects))) {
		struct callback_object *object;
		struct nt_list *ent;
		object = container_of(cur, struct callback_object, list);
		while ((ent = RemoveHeadList(&object->callback_funcs))) {
			struct callback_func *f;
			f = container_of(ent, struct callback_func, list);
			kfree(f);
		}
		kfree(object);
	}

	del_bus_drivers();

	/* delete all objects */
	while ((cur = RemoveHeadList(&object_list))) {
		struct common_object_header *header;
		header = container_of(cur, struct common_object_header, list);
		DBGTRACE3("freeing header: %p", header);
		kfree(header);
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	return;
}

int ntoskernel_init_device(struct wrapper_dev *wd)
{
	struct kthread *kthread;

	DBGTRACE1("task: %p", get_current());
	kthread = KeGetCurrentThread();
	if (kthread) {
		DBGTRACE1("kthread: %p, task: %p", kthread, kthread->task);
		return 0;
	}
	return 0;
}

void ntoskernel_exit_device(struct wrapper_dev *wd)
{
	struct kthread *kthread;

	kthread = KeGetCurrentThread();
	if (kthread) {
		DBGTRACE1("deleting thread: %p, task: %p",
			  kthread, kthread->task);
		ObDereferenceObject(kthread);
	}
	return;
}

u64 ticks_1601(void)
{
	u64 ticks;
	ticks = wrap_ticks_to_epoch +
		((u64)(jiffies - wrap_epoch) * TICKSPERSEC / HZ);
	return ticks;
}

static int add_bus_driver(struct driver_object *drv_obj, const char *name)
{
	struct bus_driver *bus_driver;
	int i;

	bus_driver = kmalloc(sizeof(*bus_driver), GFP_KERNEL);
	if (!bus_driver) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	memset(bus_driver, 0, sizeof(*bus_driver));
	strncpy(bus_driver->name, name, sizeof(bus_driver->name));
	InsertTailList(&bus_driver_list, &bus_driver->list);
	bus_driver->drv_obj = drv_obj;
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->major_func[i] = IopInvalidDeviceRequest;
	drv_obj->major_func[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		pdoDispatchInternalDeviceControl;
	drv_obj->major_func[IRP_MJ_DEVICE_CONTROL] =
		pdoDispatchDeviceControl;
	drv_obj->major_func[IRP_MJ_POWER] = pdoDispatchPower;
	drv_obj->major_func[IRP_MJ_PNP] = pdoDispatchPnp;
	DBGTRACE1("bus driver at %p", drv_obj);
	return STATUS_SUCCESS;
}

static void del_bus_drivers(void)
{
	struct nt_list *ent;
	while ((ent = RemoveHeadList(&bus_driver_list))) {
		struct bus_driver *bus_driver;
		bus_driver = container_of(ent, struct bus_driver, list);
		/* TODO: make sure all all drivers are shutdown/removed */
		kfree(bus_driver);
	}
}

struct driver_object *find_bus_driver(const char *name)
{
	struct nt_list *ent;
	nt_list_for_each(ent, &bus_driver_list) {
		struct bus_driver *bus_driver;
		bus_driver = container_of(ent, struct bus_driver, list);
		if (strcmp(bus_driver->name, name) == 0)
			return bus_driver->drv_obj;
	}
	return NULL;
}

struct device_object *alloc_pdo(struct driver_object *drv_obj)
{
	struct device_object *pdo;
	NTSTATUS res ;

	res = IoCreateDevice(drv_obj, 0, NULL, FILE_DEVICE_UNKNOWN,
			     0, FALSE, &pdo);
	DBGTRACE1("%p, %d, %p", drv_obj, res, pdo);
	if (res != STATUS_SUCCESS)
		return NULL;
	return pdo;
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExfInterlockedInsertHeadList)
	(FASTCALL_DECL_3(struct nt_list *head, struct nt_list *entry,
			 KSPIN_LOCK *lock))
{
	struct nt_list *first;
	KIRQL irql;

	TRACEENTER5("head = %p, entry = %p", head, entry);
	irql = kspin_lock_irql(lock, DISPATCH_LEVEL);
	first = InsertHeadList(head, entry);
	kspin_unlock_irql(lock, irql);
	DBGTRACE5("head = %p, old = %p", head, first);
	return first;
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExInterlockedInsertHeadList)
	(FASTCALL_DECL_3(struct nt_list *head, struct nt_list *entry,
			 KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExfInterlockedInsertHeadList(FASTCALL_ARGS_3(head, entry,
							    lock));
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExfInterlockedInsertTailList)
	(FASTCALL_DECL_3(struct nt_list *head, struct nt_list *entry,
			 KSPIN_LOCK *lock))
{
	struct nt_list *last;
	KIRQL irql;

	TRACEENTER5("head = %p, entry = %p", head, entry);
	irql = kspin_lock_irql(lock, DISPATCH_LEVEL);
	last = InsertTailList(head, entry);
	kspin_unlock_irql(lock, irql);
	DBGTRACE5("head = %p, old = %p", head, last);
	return last;
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExInterlockedInsertTailList)
	(FASTCALL_DECL_3(struct nt_list *head, struct nt_list *entry,
			 KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExfInterlockedInsertTailList(FASTCALL_ARGS_3(head, entry,
							    lock));
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExfInterlockedRemoveHeadList)
	(FASTCALL_DECL_2(struct nt_list *head, KSPIN_LOCK *lock))
{
	struct nt_list *ret;
	KIRQL irql;

	TRACEENTER5("head = %p", head);
	irql = kspin_lock_irql(lock, DISPATCH_LEVEL);
	ret = RemoveHeadList(head);
	kspin_unlock_irql(lock, irql);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExInterlockedRemoveHeadList)
	(FASTCALL_DECL_2(struct nt_list *head, KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExfInterlockedRemoveHeadList(FASTCALL_ARGS_2(head, lock));
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExfInterlockedRemoveTailList)
	(FASTCALL_DECL_2(struct nt_list *head, KSPIN_LOCK *lock))
{
	struct nt_list *ret;
	KIRQL irql;

	TRACEENTER5("head = %p", head);
	irql = kspin_lock_irql(lock, DISPATCH_LEVEL);
	ret = RemoveTailList(head);
	kspin_unlock_irql(lock, irql);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

_FASTCALL struct nt_list *WRAP_EXPORT(ExInterlockedRemoveTailList)
	(FASTCALL_DECL_2(struct nt_list *head, KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExfInterlockedRemoveTailList(FASTCALL_ARGS_2(head, lock));
}

STDCALL struct nt_slist *WRAP_EXPORT(ExpInterlockedPushEntrySList)
	(union nt_slist_head *head, struct nt_slist *entry)
{
	struct nt_slist *ret;
	KIRQL irql;

	TRACEENTER5("head = %p", head);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	ret = PushEntryList(head, entry);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

_FASTCALL struct nt_slist *WRAP_EXPORT(ExInterlockedPushEntrySList)
	(FASTCALL_DECL_3(union nt_slist_head *head, struct nt_slist *entry,
			 KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExpInterlockedPushEntrySList(head, entry);
}

_FASTCALL struct nt_slist *WRAP_EXPORT(InterlockedPushEntrySList)
	(FASTCALL_DECL_2(union nt_slist_head *head, struct nt_slist *entry))
{
	TRACEENTER5("%p", head);
	return ExpInterlockedPushEntrySList(head, entry);
}

STDCALL struct nt_slist *WRAP_EXPORT(ExpInterlockedPopEntrySList)
	(union nt_slist_head *head)
{
	struct nt_slist *ret;
	KIRQL irql;

	TRACEENTER5("head = %p", head);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	ret = PopEntryList(head);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

_FASTCALL struct nt_slist *WRAP_EXPORT(ExInterlockedPopEntrySList)
	(FASTCALL_DECL_2(union nt_slist_head *head, KSPIN_LOCK *lock))
{
	TRACEENTER5("%p", head);
	return ExpInterlockedPopEntrySList(head);
}

_FASTCALL struct nt_slist *WRAP_EXPORT(InterlockedPopEntrySList)
	(FASTCALL_DECL_1(union nt_slist_head *head))
{
	TRACEENTER5("%p", head);
	return ExpInterlockedPopEntrySList(head);
}

STDCALL USHORT WRAP_EXPORT(ExQueryDepthSList)
	(union nt_slist_head *head)
{
	TRACEENTER5("%p", head);
	return head->list.depth;
}

/* should be called with kevent_lock held at DISPATCH_LEVEL */
void initialize_dh(struct dispatch_header *dh, enum event_type type, int state,
				enum dh_type dh_type)
{
	memset(dh, 0xa3, sizeof(*dh));
	dh->type = type;
	dh->signal_state = state;
	dh->inserted = dh_type;
	InitializeListHead(&dh->wait_blocks);
}

STDCALL void WRAP_EXPORT(KeInitializeTimer)
	(struct ktimer *ktimer)
{
	KIRQL irql;

	TRACEENTER5("%p", ktimer);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	initialize_dh(&ktimer->dh, NotificationTimer, 0, DH_KTIMER);
	kspin_unlock_irql(&kevent_lock, irql);
	wrap_init_timer(ktimer, NULL, NULL, KTIMER_TYPE_KERNEL);
}

STDCALL void WRAP_EXPORT(KeInitializeTimerEx)
	(struct ktimer *ktimer, enum timer_type type)
{
	KIRQL irql;

	TRACEENTER5("%p", ktimer);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	initialize_dh(&ktimer->dh, type, 0, DH_KTIMER);
	kspin_unlock_irql(&kevent_lock, irql);
	wrap_init_timer(ktimer, NULL, NULL, KTIMER_TYPE_KERNEL);
}

STDCALL BOOLEAN WRAP_EXPORT(KeSetTimerEx)
	(struct ktimer *ktimer, LARGE_INTEGER duetime_ticks, LONG period_ms,
	 struct kdpc *kdpc)
{
	unsigned long expires;
	unsigned long repeat;

	TRACEENTER5("%p, %ld, %u, %p", ktimer, (long)duetime_ticks, period_ms, kdpc);

	expires = SYSTEM_TIME_TO_HZ(duetime_ticks);
	repeat = HZ * period_ms / 1000 ;
	return wrap_set_timer(ktimer->wrap_timer, expires, repeat, kdpc);
}

STDCALL BOOLEAN WRAP_EXPORT(KeSetTimer)
	(struct ktimer *ktimer, LARGE_INTEGER duetime_ticks, struct kdpc *kdpc)
{
	unsigned long expires;

	TRACEENTER5("%p, %ld, %p", ktimer, (long)duetime_ticks, kdpc);
	expires = SYSTEM_TIME_TO_HZ(duetime_ticks);
	return wrap_set_timer(ktimer->wrap_timer, expires, 0, kdpc);
}

STDCALL BOOLEAN WRAP_EXPORT(KeCancelTimer)
	(struct ktimer *ktimer)
{
	char canceled;

	TRACEENTER5("%p", ktimer);
	wrap_cancel_timer(ktimer->wrap_timer, &canceled);
	return canceled;
}

void initialize_kdpc(struct kdpc *kdpc, void *func, void *ctx,
		     enum kdpc_type type)
{
	TRACEENTER3("%p, %p, %p", kdpc, func, ctx);
	memset(kdpc, 0, sizeof(*kdpc));
	kdpc->number = 0;
	kdpc->type = type;
	kdpc->func = func;
	kdpc->ctx  = ctx;
	InitializeListHead(&kdpc->list);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(KeInitializeDpc)
	(struct kdpc *kdpc, void *func, void *ctx)
{
	initialize_kdpc(kdpc, func, ctx, KDPC_TYPE_KERNEL);
}

static void kdpc_worker(void *data)
{
	struct nt_list *entry;
	struct kdpc *kdpc;
	KIRQL irql;

	while (1) {
		irql = kspin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
		entry = RemoveHeadList(&kdpc_list);
		if (!entry) {
			kspin_unlock_irql(&kdpc_list_lock, irql);
			break;
		}
		kdpc = container_of(entry, struct kdpc, list);
		kdpc->number = 0;
		DBGTRACE5("%p, %p, %p, %p, %p", kdpc, dpc_func, kdpc->ctx,
			  kdpc->arg1, kdpc->arg2);
		LIN2WIN4(kdpc->func, kdpc, kdpc->ctx, kdpc->arg1, kdpc->arg2);
		kspin_unlock_irql(&kdpc_list_lock, irql);
	}
}

STDCALL void KeFlushQueuedDpcs(void)
{
	kdpc_worker(NULL);
}

BOOLEAN insert_kdpc_work(struct kdpc *kdpc)
{
	KIRQL irql;
	BOOLEAN ret;

	TRACEENTER5("%p", kdpc);
	if (!kdpc)
		return FALSE;
	if (kdpc->type != KDPC_TYPE_KERNEL)
		ERROR("kdpc type: %d", kdpc->type);
	irql = kspin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
	if (kdpc->number) {
		if (kdpc->number != 1)
			ERROR("kdpc->number: %d", kdpc->number);
		ret = FALSE;
	} else {
		kdpc->number = 1;
		InsertTailList(&kdpc_list, &kdpc->list);
		ret = TRUE;
	}
	kspin_unlock_irql(&kdpc_list_lock, irql);
	if (ret == TRUE)
		schedule_work(&kdpc_work);
	TRACEEXIT5(return ret);
}

BOOLEAN remove_kdpc_work(struct kdpc *kdpc)
{
	KIRQL irql;
	BOOLEAN ret;

	if (!kdpc)
		return FALSE;
	irql = kspin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
	if (kdpc->number) {
		if (kdpc->number != 1)
			ERROR("kdpc->number: %d", kdpc->number);
		RemoveEntryList(&kdpc->list);
		kdpc->number = 0;
		ret = TRUE;
	} else
		ret = FALSE;
	kspin_unlock_irql(&kdpc_list_lock, irql);
	return ret;
}

STDCALL BOOLEAN WRAP_EXPORT(KeInsertQueueDpc)
	(struct kdpc *kdpc, void *arg1, void *arg2)
{
	BOOLEAN ret;

	TRACEENTER5("%p, %p, %p", kdpc, arg1, arg2);
	kdpc->arg1 = arg1;
	kdpc->arg2 = arg2;
	ret = insert_kdpc_work(kdpc);
	TRACEEXIT5(return ret);
}

STDCALL BOOLEAN WRAP_EXPORT(KeRemoveQueueDpc)
	(struct kdpc *kdpc)
{
	BOOLEAN ret;

	TRACEENTER3("%p", kdpc);
	ret = remove_kdpc_work(kdpc);
	TRACEEXIT3(return ret);
}

STDCALL void WRAP_EXPORT(KeInitializeSpinLock)
	(KSPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	kspin_lock_init(lock);
}

STDCALL void WRAP_EXPORT(KeAcquireSpinLock)
	(KSPIN_LOCK *lock, KIRQL *irql)
{
	TRACEENTER6("%p", lock);
	*irql = kspin_lock_irql(lock, DISPATCH_LEVEL);
}

STDCALL void WRAP_EXPORT(KeReleaseSpinLock)
	(KSPIN_LOCK *lock, KIRQL oldirql)
{
	TRACEENTER6("%p", lock);
	kspin_unlock_irql(lock, oldirql);
}

STDCALL void WRAP_EXPORT(KeAcquireSpinLockAtDpcLevel)
	(KSPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	kspin_lock(lock);
}

STDCALL void WRAP_EXPORT(KeRaiseIrql)
	(KIRQL newirql, KIRQL *oldirql)
{
	TRACEENTER6("%d", newirql);
	*oldirql = raise_irql(newirql);
}

STDCALL KIRQL WRAP_EXPORT(KeRaiseIrqlToDpcLevel)
	(void)
{
	return raise_irql(DISPATCH_LEVEL);
}

STDCALL void WRAP_EXPORT(KeLowerIrql)
	(KIRQL irql)
{
	TRACEENTER6("%d", irql);
	lower_irql(irql);
}

STDCALL KIRQL WRAP_EXPORT(KeAcquireSpinLockRaiseToDpc)
        (KSPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	return kspin_lock_irql(lock, DISPATCH_LEVEL);
}

STDCALL void WRAP_EXPORT(KeReleaseSpinLockFromDpcLevel)
	(KSPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	kspin_unlock(lock);
}

_FASTCALL LONG WRAP_EXPORT(InterlockedDecrement)
	(FASTCALL_DECL_1(LONG volatile *val))
{
	LONG x;
	KIRQL irql;

	TRACEENTER5("%s", "");
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	(*val)--;
	x = *val;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT5(return x);
}

_FASTCALL LONG WRAP_EXPORT(InterlockedIncrement)
	(FASTCALL_DECL_1(LONG volatile *val))
{
	LONG x;
	KIRQL irql;

	TRACEENTER5("%s", "");
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	(*val)++;
	x = *val;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT5(return x);
}

_FASTCALL LONG WRAP_EXPORT(InterlockedExchange)
	(FASTCALL_DECL_2(LONG volatile *target, LONG val))
{
	LONG x;
	KIRQL irql;

	TRACEENTER5("%s", "");
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	x = *target;
	*target = val;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT5(return x);
}

_FASTCALL LONG WRAP_EXPORT(InterlockedCompareExchange)
	(FASTCALL_DECL_3(LONG volatile *dest, LONG xchg, LONG comperand))
{
	LONG x;
	KIRQL irql;

	TRACEENTER5("%s", "");
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	x = *dest;
	if (*dest == comperand)
		*dest = xchg;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT5(return x);
}

_FASTCALL void WRAP_EXPORT(ExInterlockedAddLargeStatistic)
	(FASTCALL_DECL_2(LARGE_INTEGER *plint, ULONG n))
{
	unsigned long flags;

	TRACEENTER5("%p = %llu, n = %u", plint, *plint, n);
	kspin_lock_irqsave(&ntoskernel_lock, flags);
	*plint += n;
	kspin_unlock_irqrestore(&ntoskernel_lock, flags);
}

STDCALL void *WRAP_EXPORT(ExAllocatePoolWithTag)
	(enum pool_type pool_type, SIZE_T size, ULONG tag)
{
	void *ret;

	TRACEENTER1("pool_type: %d, size: %lu, tag: %u", pool_type,
		    size, tag);

	if (current_irql() < DISPATCH_LEVEL)
		ret = kmalloc(size, GFP_KERNEL);
	else
		ret = kmalloc(size, GFP_ATOMIC);
	return ret;
}

STDCALL void WRAP_EXPORT(ExFreePool)
	(void *p)
{
	kfree(p);
}

WRAP_FUNC_PTR_DECL(ExAllocatePoolWithTag)
WRAP_FUNC_PTR_DECL(ExFreePool)

STDCALL void WRAP_EXPORT(ExInitializeNPagedLookasideList)
	(struct npaged_lookaside_list *lookaside,
	 LOOKASIDE_ALLOC_FUNC *alloc_func, LOOKASIDE_FREE_FUNC *free_func,
	 ULONG flags, SIZE_T size, ULONG tag, USHORT depth)
{
	TRACEENTER3("lookaside: %p, size: %lu, flags: %u,"
		    " head: %p, alloc: %p, free: %p",
		    lookaside, size, flags, lookaside->head.list.next,
		    alloc_func, free_func);

	memset(lookaside, 0, sizeof(*lookaside));

	lookaside->size = size;
	lookaside->tag = tag;
	lookaside->depth = 4;
	lookaside->maxdepth = 256;
	lookaside->pool_type = NonPagedPool;

	if (alloc_func)
		lookaside->alloc_func = alloc_func;
	else
		lookaside->alloc_func = (LOOKASIDE_ALLOC_FUNC *)
		  WRAP_FUNC_PTR(ExAllocatePoolWithTag);
	if (free_func)
		lookaside->free_func = free_func;
	else
		lookaside->free_func = (LOOKASIDE_FREE_FUNC *)
		  WRAP_FUNC_PTR(ExFreePool);

#ifndef X86_64
	DBGTRACE3("lock: %p", &lookaside->obsolete);
	kspin_lock_init(&lookaside->obsolete);
#endif
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(ExDeleteNPagedLookasideList)
	(struct npaged_lookaside_list *lookaside)
{
	struct nt_slist *entry;
	KIRQL irql;

	TRACEENTER3("lookaside = %p", lookaside);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((entry = ExpInterlockedPopEntrySList(&lookaside->head)))
		ExFreePool(entry);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT5(return);
}

STDCALL NTSTATUS WRAP_EXPORT(ExCreateCallback)
	(struct callback_object **object, struct object_attributes *attributes,
	 BOOLEAN create, BOOLEAN allow_multiple_callbacks)
{
	struct callback_object *obj;
	struct nt_list *cur;
	KIRQL irql;

	TRACEENTER2("");
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each(cur, &callback_objects) {
		obj = container_of(cur, struct callback_object,
				   callback_funcs);
		if (obj->attributes == attributes) {
			kspin_unlock_irql(&ntoskernel_lock, irql);
			*object = obj;
			return STATUS_SUCCESS;
		}
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
	InitializeListHead(&obj->callback_funcs);
	kspin_lock_init(&obj->lock);
	obj->allow_multiple_callbacks = allow_multiple_callbacks;
	obj->attributes = attributes;
	*object = obj;
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL void *WRAP_EXPORT(ExRegisterCallback)
	(struct callback_object *object, PCALLBACK_FUNCTION func,
	 void *context)
{
	struct callback_func *callback;
	KIRQL irql;

	TRACEENTER2("");
	irql = kspin_lock_irql(&object->lock, DISPATCH_LEVEL);
	if (object->allow_multiple_callbacks == FALSE &&
	    !IsListEmpty(&object->callback_funcs)) {
		kspin_unlock_irql(&object->lock, irql);
		TRACEEXIT2(return NULL);
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	callback = kmalloc(sizeof(*callback), GFP_KERNEL);
	if (!callback) {
		ERROR("couldn't allocate memory");
		return NULL;
	}
	callback->func = func;
	callback->context = context;
	callback->object = object;
	irql = kspin_lock_irql(&object->lock, DISPATCH_LEVEL);
	InsertTailList(&object->callback_funcs, &callback->list);
	kspin_unlock_irql(&object->lock, irql);
	TRACEEXIT2(return callback);
}

STDCALL void WRAP_EXPORT(ExUnregisterCallback)
	(struct callback_func *callback)
{
	struct callback_object *object;
	KIRQL irql;

	TRACEENTER3("%p", callback);
	if (!callback)
		return;
	object = callback->object;
	irql = kspin_lock_irql(&object->lock, DISPATCH_LEVEL);
	RemoveEntryList(&callback->list);
	kspin_unlock_irql(&object->lock, irql);
	return;
}

STDCALL void WRAP_EXPORT(ExNotifyCallback)
	(struct callback_object *object, void *arg1, void *arg2)
{
	struct nt_list *cur;
	struct callback_func *callback;
	KIRQL irql;

	TRACEENTER3("%p", object);
	irql = kspin_lock_irql(&object->lock, DISPATCH_LEVEL);
	nt_list_for_each(cur, &object->callback_funcs){
		callback = container_of(cur, struct callback_func, list);
		LIN2WIN3(callback->func, callback->context, arg1, arg2);
	}
	kspin_unlock_irql(&object->lock, irql);
	return;
}

STDCALL void WRAP_EXPORT(KeInitializeEvent)
	(struct kevent *kevent, enum event_type type, BOOLEAN state)
{
	KIRQL irql;

	DBGINFO("event = %p, type = %d, state = %d", kevent, type, state);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	initialize_dh(&kevent->dh, type, state, DH_KEVENT);
	kspin_unlock_irql(&kevent_lock, irql);
	TRACEEXIT5(return);
}

/* check and set signaled state; should be called with kevent_lock held */
static BOOLEAN inline check_reset_signaled_state(void *object, task_t *thread)
{
	struct dispatch_header *dh;
	struct kmutex *kmutex;
	BOOLEAN ret;

	dh = object;
	kmutex = container_of(object, struct kmutex, dh);
	ret = FALSE;

#if 0
	if (dh->signal_state > 0) {
		if (dh->type == SynchronizationEvent)
			dh->signal_state--;
		ret = TRUE;
	}
	/* if mutex object, this thread can grab if no other thread
	 * owns it or it already grabbed it earlier, in which case the
	 * value of signal_state can be negative */
	if (is_mutex_object(dh) &&
	    (kmutex->owner_thread == NULL ||
	     kmutex->owner_thread == thread)) {
		kmutex->owner_thread = thread;
		ret = TRUE;
	}
#else
	if (dh->signal_state > 0) {
		if (dh->type == SynchronizationEvent)
			dh->signal_state--;
		if (is_mutex_object(dh)) {
			if (kmutex->owner_thread != NULL)
				WARNING("mutex: %d, %p", dh->signal_state,
					kmutex->owner_thread);
			kmutex->owner_thread = thread;
		}
		ret = TRUE;
	} else {
		if (is_mutex_object(dh)) {
			if (kmutex->owner_thread == NULL)
				WARNING("mutex: %d", dh->signal_state);
			if (kmutex->owner_thread == thread) {
				dh->signal_state--;
				ret = TRUE;
			}
		}
	}
#endif
	return ret;
}

/* this function should be called holding kevent_lock spinlock at
 * DISPATCH_LEVEL */
static void wakeup_threads(struct dispatch_header *dh)
{
	struct nt_list *cur, *tmp;
	KIRQL irql;
	struct wait_block *wb;

	DBGINFO("dh: %p", dh);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	nt_list_for_each_safe(cur, tmp, &dh->wait_blocks) {
		wb = container_of(cur, struct wait_block, list);
		DBGINFO("wait block: %p", wb);
		if (check_reset_signaled_state(dh, wb->thread)) {
			/* mark that this thread is done */
			wb->object = NULL;
			RemoveEntryList(cur);
			DBGINFO("waking up process: %p", wb->thread);
			wake_up_process(wb->thread);
		}
	}
	kspin_unlock_irql(&kevent_lock, irql);
	return;
}

STDCALL LONG WRAP_EXPORT(KeSetEvent)
	(struct kevent *kevent, KPRIORITY incr, BOOLEAN wait)
{
	LONG old_state;
	KIRQL irql;

	DBGINFO("event = %p, type = %d, wait = %d",
		    kevent, kevent->dh.type, wait);
	if (wait == TRUE)
		WARNING("wait = %d, not yet implemented", wait);

	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	old_state = kevent->dh.signal_state;
	kevent->dh.signal_state = 1;
	kspin_unlock_irql(&kevent_lock, irql);
	wakeup_threads(&kevent->dh);
	DBGINFOEXIT(return old_state);
}

STDCALL void WRAP_EXPORT(KeClearEvent)
	(struct kevent *kevent)
{
	KIRQL irql;

	DBGINFO("event = %p", kevent);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	kevent->dh.signal_state = 0;
	kspin_unlock_irql(&kevent_lock, irql);
	TRACEEXIT5(return);
}

STDCALL LONG WRAP_EXPORT(KeResetEvent)
	(struct kevent *kevent)
{
	LONG old_state;
	KIRQL irql;

	DBGINFO("event = %p", kevent);

	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	old_state = kevent->dh.signal_state;
	kevent->dh.signal_state = 0;
	kspin_unlock_irql(&kevent_lock, irql);

	TRACEEXIT5(return old_state);
}

STDCALL void WRAP_EXPORT(KeInitializeMutex)
	(struct kmutex *kmutex, BOOLEAN wait)
{
	KIRQL irql;

	DBGINFO("%p", kmutex);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	initialize_dh(&kmutex->dh, SynchronizationEvent, 1, DH_KMUTEX);
	kspin_unlock_irql(&kevent_lock, irql);
	kmutex->dh.size = sizeof(*kmutex);
	InitializeListHead(&kmutex->list);
	kmutex->abandoned = FALSE;
	kmutex->apc_disable = 1;
	kmutex->owner_thread = NULL;
	return;
}

STDCALL LONG WRAP_EXPORT(KeReleaseMutex)
	(struct kmutex *kmutex, BOOLEAN wait)
{
	LONG ret;
	KIRQL irql;

	DBGINFO("%p", kmutex);
	if (wait == TRUE)
		WARNING("wait: %d", wait);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	ret = kmutex->dh.signal_state++;
	kspin_unlock_irql(&kevent_lock, irql);
	if (ret >= 0)
		wakeup_threads(&kmutex->dh);
	return ret;
}

STDCALL void WRAP_EXPORT(KeInitializeSemaphore)
	(struct ksemaphore *ksemaphore, LONG count, LONG limit)
{
	KIRQL irql;

	DBGINFO("%p: %d", ksemaphore, count);
	/* if limit > 1, we need to satisfy as many waits (until count
	 * becomes 0); so we set it as notification event, and keep
	 * decrementing count everytime a wait is satisified */
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	initialize_dh(&ksemaphore->dh, SynchronizationEvent, count,
		      DH_KSEMAPHORE);
	kspin_unlock_irql(&kevent_lock, irql);
	ksemaphore->dh.size = sizeof(*ksemaphore);
	ksemaphore->limit = limit;
}

STDCALL LONG WRAP_EXPORT(KeReleaseSemaphore)
	(struct ksemaphore *ksemaphore, KPRIORITY incr, LONG adjustment,
	 BOOLEAN wait)
{
	LONG ret;
	KIRQL irql;

	DBGINFO("%p", ksemaphore);
	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	ret = ksemaphore->dh.signal_state;
	if (ret <= 0)
		ret = 0;
	ksemaphore->dh.signal_state += adjustment;
	if (ksemaphore->dh.signal_state > ksemaphore->limit)
		ksemaphore->dh.signal_state = ksemaphore->limit;
	kspin_unlock_irql(&kevent_lock, irql);
	wakeup_threads(&ksemaphore->dh);
	return ret;
}

STDCALL NTSTATUS WRAP_EXPORT(KeWaitForMultipleObjects)
	(ULONG count, void *object[], enum wait_type wait_type,
	 KWAIT_REASON wait_reason, KPROCESSOR_MODE wait_mode,
	 BOOLEAN alertable, LARGE_INTEGER *timeout,
	 struct wait_block *wait_block_array)
{
	int i, res = 0, wait_count;
	long wait_jiffies = 0;
	struct wait_block *wb, wb_array[THREAD_WAIT_OBJECTS];
	struct dispatch_header *dh;
	KIRQL irql;

	DBGINFO("count = %d, reason = %u, waitmode = %u, alertable = %u,"
		    " timeout = %p", count, wait_reason, wait_mode,
		    alertable, timeout);

	if (count > MAX_WAIT_OBJECTS)
		TRACEEXIT4(return STATUS_INVALID_PARAMETER);
	if (count > THREAD_WAIT_OBJECTS && wait_block_array == NULL)
		TRACEEXIT4(return STATUS_INVALID_PARAMETER);

	if (wait_block_array == NULL)
		wb = &wb_array[0];
	else
		wb = wait_block_array;

	alertable = TRUE;
	if (timeout) {
		DBGINFO("timeout = %Ld", *timeout);
		if (*timeout == 0) {
			irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
			for (i = 0, wait_count = 0; i < count; i++)
				/* TODO: only check or set signaled
				 * state too? */
				if (!check_reset_signaled_state(object[i],
								get_current()))
					wait_count++;
			kspin_unlock_irql(&kevent_lock, irql);
			if (wait_count)
				DBGINFOEXIT(return STATUS_TIMEOUT);
			else
				DBGINFOEXIT(return STATUS_SUCCESS);
		} else 
			wait_jiffies = SYSTEM_TIME_TO_HZ(*timeout);
	} else
		wait_jiffies = 0;

	irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
	/* first get the list of objects the thread need to wait on
	 * and add it on the wait list for each such object */
	for (i = 0, wait_count = 0; i < count; i++) {
		dh = object[i];
		if (check_reset_signaled_state(dh, get_current())) {
			DBGINFO("%p is already signaled", dh);
			if (wait_type == WaitAny) {
				kspin_unlock_irql(&kevent_lock, irql);
				DBGINFOEXIT(return STATUS_WAIT_0 + i);
			}
			/* mark that we are not waiting on this object */
			wb[i].thread = NULL;
			wb[i].object = NULL;
		} else {
			wb[i].thread = get_current();
			wb[i].object = dh;
			InsertTailList(&dh->wait_blocks, &wb[i].list);
			wait_count++;
			DBGINFO("%p (%p) waiting on event %p", &wb[i],
				  wb[i].thread, dh);
		}
	}
	if (wait_count == 0) {
		kspin_unlock_irql(&kevent_lock, irql);
		DBGINFOEXIT(return STATUS_SUCCESS);
	}

	/* we put the task state in appropriate state before releasing
	 * the spinlock, so that if the event is set to signaled state
	 * after putting the thread on the wait list but before we put
	 * the thread into sleep (with 'schedule'), wakup_event will
	 * put the thread back into running state; otherwise,
	 * wakeup_threads may put this into running state and _then_ we
	 * go to sleep causing thread to miss the event */
	if (alertable)
		set_current_state(TASK_INTERRUPTIBLE);
	else
		set_current_state(TASK_UNINTERRUPTIBLE);
	kspin_unlock_irql(&kevent_lock, irql);

	DBGINFO("%p is going to sleep for %ld", get_current(), wait_jiffies);
	while (wait_count) {
		if (wait_jiffies > 0)
			res = schedule_timeout(wait_jiffies);
		else {
			schedule();
			res = 1;
		}
		if (signal_pending(current))
			res = -ERESTARTSYS;
		irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
		DBGINFO("%p woke up, res = %d", get_current(), res);
		if (res <= 0) {
			/* timed out or interrupted; remove from wait list */
			for (i = 0; i < count; i++) {
				if (!wb[i].thread)
					continue;
				if (!wb[i].object) {
					ERROR("%p already dequeud by %p",
					      get_current(), object[i]);
					continue;
				}
				DBGINFO("%d: %p", i, &wb[i].list);
				RemoveEntryList(&wb[i].list);
				wb[i].object = NULL;
				wb[i].thread = NULL;
			}
			kspin_unlock_irql(&kevent_lock, irql);
			if (res < 0)
				DBGINFOEXIT(return STATUS_ALERTED);
			if (res == 0)
				DBGINFOEXIT(return STATUS_TIMEOUT);
		}
		/* woken up by wakeup_threads */
		for (i = 0; wait_count && i < count; i++) {
			/* only if wb[i].thread is not NULL and
			 * wb[i].object is NULL this thread is woken
			 * up for this dh */
			if (!wb[i].thread)
				continue;
			if (wb[i].object)
				continue;
			dh = object[i];
			wait_count--;
			if (wait_type == WaitAny) {
				int j;
				/* done; remove from rest of wait list */
				for (j = i; j < count; j++)
					if (wb[j].thread && wb[j].object)
						RemoveEntryList(&wb[j].list);
				kspin_unlock_irql(&kevent_lock, irql);
				DBGINFOEXIT(return STATUS_WAIT_0 + i);
			}
		}
		if (wait_count == 0) {
			kspin_unlock_irql(&kevent_lock, irql);
			DBGINFOEXIT(return STATUS_SUCCESS);
		}
		/* this thread is still waiting for more objects, so
		 * let it wait for remaining time and those objects */
		wait_jiffies = res;
		if (alertable)
			set_current_state(TASK_INTERRUPTIBLE);
		else
			set_current_state(TASK_UNINTERRUPTIBLE);
		kspin_unlock_irql(&kevent_lock, irql);
	}
	/* this should never reach, but compiler wants return value */
	set_current_state(TASK_RUNNING);
	TRACEEXIT4(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(KeWaitForSingleObject)
	(void *object, KWAIT_REASON wait_reason, KPROCESSOR_MODE wait_mode,
	 BOOLEAN alertable, LARGE_INTEGER *timeout)
{
	return KeWaitForMultipleObjects(1, &object, WaitAll, wait_reason,
					wait_mode, alertable, timeout, NULL);
}

STDCALL NTSTATUS WRAP_EXPORT(KeDelayExecutionThread)
	(KPROCESSOR_MODE wait_mode, BOOLEAN alertable,
	 LARGE_INTEGER *interval)
{
	int res;
	long timeout;

	if (wait_mode != 0)
		ERROR("invalid wait_mode %d", wait_mode);

	timeout = SYSTEM_TIME_TO_HZ(*interval) + 1;

	TRACEENTER4("thread: %p, interval: %Ld, timeout: %ld",
		    get_current(), *interval, timeout);
	if (timeout <= 0)
		TRACEEXIT3(return STATUS_SUCCESS);

	if (alertable)
		set_current_state(TASK_INTERRUPTIBLE);
	else
		set_current_state(TASK_UNINTERRUPTIBLE);

	res = schedule_timeout(timeout);
	DBGTRACE4("thread: %p, res: %d", get_current(), res);
	if (res == 0)
		TRACEEXIT3(return STATUS_SUCCESS);
	else
		TRACEEXIT3(return STATUS_ALERTED);
}

STDCALL KPRIORITY WRAP_EXPORT(KeQueryPriorityThread)
	(struct kthread *kthread)
{
	KPRIORITY prio;

	TRACEENTER4("thread: %p, task: %p", kthread, kthread->task);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	prio = 1;
#else
	if (rt_task(kthread->task))
		prio = LOW_REALTIME_PRIORITY;
	else
		prio = MAXIMUM_PRIORITY;
#endif
	TRACEEXIT5(return prio);
}

STDCALL ULONGLONG WRAP_EXPORT(KeQueryInterruptTime)
	(void)
{
	TRACEEXIT5(return jiffies * TICKSPERSEC / HZ);
}

STDCALL ULONG WRAP_EXPORT(KeQueryTimeIncrement)
	(void)
{
	TRACEEXIT5(return TICKSPERSEC / HZ);
}

STDCALL void WRAP_EXPORT(KeQuerySystemTime)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
	return;
}

STDCALL LARGE_INTEGER WRAP_EXPORT(KeQueryPerformanceCounter)
	(LARGE_INTEGER *counter)
{
	unsigned long res;

	res = jiffies;
	if (counter)
		*counter = res;
	return res;
}

STDCALL struct kthread *WRAP_EXPORT(KeGetCurrentThread)
	(void)
{
	struct nt_list *cur;
	KIRQL irql;
	task_t *task = get_current();
	struct kthread *ret;

	DBGTRACE3("task: %p", task);
	ret = NULL;
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each(cur, &object_list) {
		struct common_object_header *header;
		struct kthread *kthread;
		header = container_of(cur, struct common_object_header, list);
		DBGTRACE1("header: %p, type: %d", header, header->type);
		if (header->type != OBJECT_TYPE_KTHREAD)
			continue;
		kthread = HEADER_TO_OBJECT(header);
		DBGTRACE3("kthread: %p, task: %p", kthread, kthread->task);
		if (kthread->task == task) {
			ret = kthread;
			break;
		}
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE3("current thread = %p", ret);
	return ret;
}

STDCALL KPRIORITY WRAP_EXPORT(KeSetPriorityThread)
	(struct kthread *kthread, KPRIORITY priority)
{
	KPRIORITY old_prio;

	TRACEENTER4("thread: %p, priority = %u", kthread, priority);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	/* FIXME: is there a way to set kernel thread prio on 2.4? */
	old_prio = LOW_PRIORITY;
#else
	if (rt_task(kthread->task))
		old_prio = LOW_REALTIME_PRIORITY;
	else
		old_prio = MAXIMUM_PRIORITY;
#if 0
	if (priority == LOW_REALTIME_PRIORITY)
		set_user_nice(kthread->task, -20);
	else
		set_user_nice(kthread->task, 10);
#endif
#endif
	return old_prio;
}

struct trampoline_context {
	void (*start_routine)(void *) STDCALL;
	void *context;
};

int kthread_trampoline(void *data)
{
	struct trampoline_context ctx;

	memcpy(&ctx, data, sizeof(ctx));
	kfree(data);

	ctx.start_routine(ctx.context);

	return 0;
}

struct kthread *wrap_create_current_thread(void)
{
	struct kthread *kthread;
	KIRQL irql;

	kthread = ALLOCATE_OBJECT(struct kthread, GFP_KERNEL,
				  OBJECT_TYPE_KTHREAD);
	if (kthread) {
		kthread->task = get_current();
		kthread->pid = kthread->task->pid;
		kspin_lock_init(&kthread->lock);
		InitializeListHead(&kthread->irps);
		irql = kspin_lock_irql(&kevent_lock, DISPATCH_LEVEL);
		initialize_dh(&kthread->dh, SynchronizationEvent,
			      0, DH_KTHREAD);
		kspin_unlock_irql(&kevent_lock, irql);
		kthread->dh.size = sizeof(*kthread);

		DBGTRACE2("kthread: %p, task: %p, pid: %d",
			  kthread, kthread->task, kthread->pid);
	} else
		ERROR("couldn't allocate thread object");
	return kthread;
}

void wrap_remove_current_thread(void)
{
	struct kthread *kthread;
	KIRQL irql;
	struct nt_list *ent;

	kthread = KeGetCurrentThread();
	if (kthread) {
		DBGTRACE2("terminating thread: %p, task: %p, pid: %d",
			  kthread, kthread->task, kthread->task->pid);
		irql = kspin_lock_irql(&kthread->lock, DISPATCH_LEVEL);
		while ((ent = RemoveHeadList(&kthread->irps))) {
			struct irp *irp;

			irp = container_of(ent, struct irp, threads);
			if (!irp->cancel)
				IoCancelIrp(irp);
		}
		kspin_unlock_irql(&kthread->lock, irql);
		ObDereferenceObject(kthread);
	} else
		ERROR("couldn't find thread for task: %p", get_current());
	return;
}

STDCALL NTSTATUS WRAP_EXPORT(PsCreateSystemThread)
	(void **phandle, ULONG access, void *obj_attr, void *process,
	 void *client_id, void (*start_routine)(void *) STDCALL, void *context)
{
	struct trampoline_context *ctx;
	struct kthread *kthread;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	int pid;
#endif

	TRACEENTER2("phandle = %p, access = %u, obj_attr = %p, process = %p, "
	            "client_id = %p, start_routine = %p, context = %p",
	            phandle, access, obj_attr, process, client_id,
	            start_routine, context);

	ctx = kmalloc(sizeof(struct trampoline_context), GFP_KERNEL);
	if (!ctx)
		TRACEEXIT2(return STATUS_RESOURCES);
	/* we create thread with current task, but will change task
	 * and pid members to newly created task and pid below */
	kthread = wrap_create_current_thread();
	if (!kthread) {
		kfree(ctx);
		TRACEEXIT2(return STATUS_RESOURCES);
	}
	ctx->start_routine = start_routine;
	ctx->context = context;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	pid = kernel_thread(kthread_trampoline, ctx,
		CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	DBGTRACE2("pid = %d", pid);
	if (pid < 0) {
		kfree(ctx);
		FREE_OBJECT(kthread);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	kthread->pid = pid;
	kthread->task = find_task_by_pid(pid);
#else
	kthread->task = kthread_create(kthread_trampoline, ctx, DRIVER_NAME);
	if (IS_ERR(kthread->task)) {
		kfree(ctx);
		FREE_OBJECT(kthread);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	kthread->pid = kthread->task->pid;
	*phandle = kthread;
	wake_up_process(kthread->task);
#endif
	DBGTRACE2("created thread: %p, task: %p, pid: %d",
		  kthread, kthread->task, kthread->pid);
	DBGTRACE2("*phandle = %p", *phandle);
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(PsTerminateSystemThread)
	(NTSTATUS status)
{
	struct kthread *kthread;

	kthread = KeGetCurrentThread();
	if (kthread) {
		DBGTRACE2("setting event for thread: %p", kthread);
		KeSetEvent((struct kevent *)&kthread->dh, 0, FALSE);
		DBGTRACE2("set event for thread: %p", kthread);
		wrap_remove_current_thread();
		complete_and_exit(NULL, status);
		ERROR("oops: %p, %d", kthread->task, kthread->pid);
	} else
		ERROR("couldn't find thread for task: %p", get_current);
	return STATUS_FAILURE;
}

STDCALL BOOLEAN WRAP_EXPORT(KeRemoveEntryDeviceQueue)
	(struct kdevice_queue *dev_queue, struct kdevice_queue_entry *entry)
{
	struct nt_list *cur;
	KIRQL irql;

	irql = kspin_lock_irql(&dev_queue->lock, DISPATCH_LEVEL);
	nt_list_for_each(cur, &dev_queue->list) {
		struct kdevice_queue_entry *e;
		e = container_of(cur, struct kdevice_queue_entry, list);
		if (e == entry) {
			RemoveEntryList(cur);
			kspin_unlock_irql(&dev_queue->lock, irql);
			return TRUE;
		}
	}
	kspin_unlock_irql(&dev_queue->lock, irql);
	return FALSE;
}

STDCALL BOOLEAN WRAP_EXPORT(KeSynchronizeExecution)
	(struct kinterrupt *interrupt, PKSYNCHRONIZE_ROUTINE synch_routine,
	 void *synch_context)
{
	KSPIN_LOCK *spinlock;
	BOOLEAN ret;
	KIRQL irql = PASSIVE_LEVEL;

	if (interrupt->actual_lock)
		spinlock = interrupt->actual_lock;
	else
		spinlock = &interrupt->lock;
	if (interrupt->synch_irql == DISPATCH_LEVEL)
		irql = kspin_lock_irql(spinlock, interrupt->synch_irql);
	else
		kspin_lock(spinlock);
	ret = synch_routine(synch_context);
	if (interrupt->synch_irql == DISPATCH_LEVEL)
		kspin_unlock_irql(spinlock, irql);
	else
		kspin_unlock(spinlock);
	return ret;
}

STDCALL void *WRAP_EXPORT(MmMapIoSpace)
	(PHYSICAL_ADDRESS phys_addr, SIZE_T size,
	 enum memory_caching_type cache)
{
	void *virt;

	if (cache)
		virt = ioremap(phys_addr, size);
	else
		virt = ioremap_nocache(phys_addr, size);
	DBGTRACE3("%Lx, %lu, %d: %p", phys_addr, size, cache, virt);
	return virt;
}

STDCALL void WRAP_EXPORT(MmUnmapIoSpace)
	(void *addr, SIZE_T size)
{
	TRACEENTER3("%p, %lu", addr, size);
	iounmap(addr);
	return;
}

STDCALL ULONG WRAP_EXPORT(MmSizeOfMdl)
	(void *base, ULONG length)
{
	return (sizeof(struct mdl) +
		SPAN_PAGES((ULONG_PTR)base, length) * sizeof(ULONG));
}

struct mdl *allocate_init_mdl(void *virt, ULONG length)
{
	struct wrap_mdl *wrap_mdl;
	struct mdl *mdl = NULL;
	int mdl_size = MmSizeOfMdl(virt, length);
	KIRQL irql;

	if (mdl_size <= CACHE_MDL_SIZE) {
		wrap_mdl = kmem_cache_alloc(mdl_cache, GFP_ATOMIC);
		if (!wrap_mdl)
			return NULL;
		DBGTRACE3("allocated mdl cache: %p", wrap_mdl);
		irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		InsertHeadList(&wrap_mdl_list, &wrap_mdl->list);
		kspin_unlock_irql(&ntoskernel_lock, irql);
		mdl = (struct mdl *)wrap_mdl->mdl;
		memset(mdl, 0, CACHE_MDL_SIZE);
		MmInitializeMdl(mdl, virt, length);
		/* mark the MDL as allocated from cache pool so when
		 * it is freed, we free it back to the pool */
		mdl->flags = MDL_CACHE_ALLOCATED;
	} else {
		wrap_mdl =
			kmalloc(sizeof(*wrap_mdl) + mdl_size - CACHE_MDL_SIZE,
				GFP_ATOMIC);
		if (!wrap_mdl)
			return NULL;
		DBGTRACE3("allocated mdl: %p", wrap_mdl);
		mdl = (struct mdl *)wrap_mdl->mdl;
		irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		InsertHeadList(&wrap_mdl_list, &wrap_mdl->list);
		kspin_unlock_irql(&ntoskernel_lock, irql);
		memset(mdl, 0, mdl_size);
		MmInitializeMdl(mdl, virt, length);
	}
	return mdl;
}

void free_mdl(struct mdl *mdl)
{
	KIRQL irql;

	/* A driver may allocate Mdl with NdisAllocateBuffer and free
	 * with IoFreeMdl (e.g., 64-bit Broadcom). Since we need to
	 * treat buffers allocated with Ndis calls differently, we
	 * must call NdisFreeBuffer if it is allocated with Ndis
	 * function. We set 'process' field in Ndis functions. */
	if (!mdl)
		return;

	if (mdl->process)
		NdisFreeBuffer(mdl);
	else {
		struct wrap_mdl *wrap_mdl;
		wrap_mdl = (struct wrap_mdl *)
			((char *)mdl - offsetof(struct wrap_mdl, mdl));
		irql = kspin_lock_irql(&ntoskernel_lock,
				       DISPATCH_LEVEL);
		RemoveEntryList(&wrap_mdl->list);
		kspin_unlock_irql(&ntoskernel_lock, irql);
		
		if (mdl->flags & MDL_CACHE_ALLOCATED) {
			DBGTRACE3("freeing mdl cache: %p (%hu)",
				  wrap_mdl, mdl->flags);
			kmem_cache_free(mdl_cache, wrap_mdl);
		} else {
			DBGTRACE3("freeing mdl: %p (%hu)",
				  wrap_mdl, mdl->flags);
			kfree(wrap_mdl);
		}
	}
	return;
}

STDCALL void WRAP_EXPORT(IoBuildPartialMdl)
	(struct mdl *source, struct mdl *target, void *virt, ULONG length)
{
	MmInitializeMdl(target, virt, length);
}

/* FIXME: We don't update MDL to physical page mapping, since in Linux
 * the pages are in memory anyway; if a driver treats an MDL as
 * opaque, we should be safe; otherwise, the driver may break */
STDCALL void WRAP_EXPORT(MmBuildMdlForNonPagedPool)
	(struct mdl *mdl)
{
	mdl->flags |= MDL_SOURCE_IS_NONPAGED_POOL;
	mdl->mappedsystemva = MmGetMdlVirtualAddress(mdl);
	return;
}

STDCALL void *WRAP_EXPORT(MmMapLockedPages)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode)
{
	mdl->flags |= MDL_MAPPED_TO_SYSTEM_VA;
	return MmGetMdlVirtualAddress(mdl);
}

STDCALL void *WRAP_EXPORT(MmMapLockedPagesSpecifyCache)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode,
	 enum memory_caching_type cache_type, void *base_address,
	 ULONG bug_check, enum mm_page_priority priority)
{
	return MmMapLockedPages(mdl, access_mode);
}

STDCALL void WRAP_EXPORT(MmUnmapLockedPages)
	(void *base, struct mdl *mdl)
{
	mdl->flags &= ~MDL_MAPPED_TO_SYSTEM_VA;
	return;
}

STDCALL void WRAP_EXPORT(MmProbeAndLockPages)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode,
	 enum lock_operation operation)
{
	mdl->flags |= MDL_PAGES_LOCKED;
	return;
}

STDCALL void WRAP_EXPORT(MmUnlockPages)
	(struct mdl *mdl)
{
	mdl->flags &= ~MDL_PAGES_LOCKED;
	return;
}

STDCALL BOOLEAN WRAP_EXPORT(MmIsAddressValid)
	(void *virt_addr)
{
	if (virt_addr_valid(virt_addr))
		return TRUE;
	else
		return FALSE;
}

STDCALL void *WRAP_EXPORT(MmLockPagableDataSection)
	(void *address)
{
	return address;
}

STDCALL void WRAP_EXPORT(MmUnlockPagableImageSection)
	(void *handle)
{
	return;
}

STDCALL NTSTATUS WRAP_EXPORT(ObReferenceObjectByHandle)
	(void *handle, ACCESS_MASK desired_access, void *obj_type,
	 KPROCESSOR_MODE access_mode, void **object, void *handle_info)
{
	struct common_object_header *hdr;
	KIRQL irql;

	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = HANDLE_TO_HEADER(handle);
	hdr->ref_count++;
	*object = HEADER_TO_OBJECT(hdr);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	return STATUS_SUCCESS;
}

/* DDK doesn't say if return value should be before incrementing or
 * after incrementing reference count, but according to #reactos
 * devels, it should be return value after incrementing */
_FASTCALL LONG WRAP_EXPORT(ObfReferenceObject)
	(FASTCALL_DECL_1(void *object))
{
	struct common_object_header *hdr;
	KIRQL irql;
	LONG ret;

	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = OBJECT_TO_HEADER(object);
	ret = ++hdr->ref_count;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	return ret;
}

_FASTCALL void WRAP_EXPORT(ObfDereferenceObject)
	(FASTCALL_DECL_1(void *object))
{
	struct common_object_header *hdr;
	KIRQL irql;

	TRACEENTER2("object: %p", object);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = OBJECT_TO_HEADER(object);
	DBGTRACE2("hdr: %p", hdr);
	hdr->ref_count--;
	if (hdr->ref_count < 0)
		ERROR("invalid object: %p (%d)", object, hdr->ref_count);
	if (hdr->ref_count <= 0)
		FREE_OBJECT(object);
	kspin_unlock_irql(&ntoskernel_lock, irql);
}

STDCALL NTSTATUS WRAP_EXPORT(ZwCreateFile)
	(void **handle, ULONG access_mask, struct object_attr *obj_attr,
	 struct io_status_block *iosb, LARGE_INTEGER *size,
	 ULONG file_attr, ULONG share_access, ULONG create_disposition,
	 ULONG create_options, void *ea_buffer, ULONG ea_length)
{
	struct nt_list *cur;
	struct object_attr *oa;
	struct ansi_string ansi;
	struct ndis_bin_file *file;
	KIRQL irql;

	ansi.buf = kmalloc(MAX_STR_LEN, GFP_KERNEL);
	if (!ansi.buf) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	ansi.buf[MAX_STR_LEN-1] = 0;
	ansi.buflen = MAX_STR_LEN;

	if (RtlUnicodeStringToAnsiString(&ansi, &obj_attr->name, 0)) {
		RtlFreeAnsiString(&ansi);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	DBGTRACE2("Filename: %s", ansi.buf);

	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each(cur, &object_list) {
		struct common_object_header *header;

		header = container_of(cur, struct common_object_header, list);
		if (header->type != OBJECT_TYPE_FILE)
			continue;
		oa = HEADER_TO_OBJECT(header);
		if (!RtlCompareUnicodeString(&oa->name, &obj_attr->name,
					     FALSE)) {
			*handle = header;
			iosb->status = FILE_OPENED;
			kspin_unlock_irql(&ntoskernel_lock, irql);
			return STATUS_SUCCESS;
		}
	}

	oa = ALLOCATE_OBJECT(struct object_attr, GFP_ATOMIC, OBJECT_TYPE_FILE);
	oa->name.buf = kmalloc(obj_attr->name.buflen, GFP_KERNEL);
	oa->name.len = oa->name.buflen = obj_attr->name.buflen;
	if (!oa->name.buf) {
		kspin_unlock_irql(&ntoskernel_lock, irql);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyUnicodeString(&oa->name, &obj_attr->name);
	*handle = OBJECT_TO_HEADER(oa);
	/* Loop through all drivers and all files to find the requested file */
	nt_list_for_each(cur, &ndis_drivers) {
		struct ndis_driver *driver;
		int i;

		driver = container_of(cur, struct ndis_driver, list);
		for (i = 0; i < driver->num_bin_files; i++) {
			int n;
			file = &driver->bin_files[i];
			DBGTRACE2("considering %s", file->name);
			n = min(strlen(file->name), strlen(ansi.buf));
			if (strnicmp(file->name, ansi.buf, n) == 0) {
				oa->file = file;
				iosb->status = FILE_OPENED;
				iosb->status_info = file->size;
				RtlFreeAnsiString(&ansi);
				kspin_unlock_irql(&ntoskernel_lock, irql);
				return STATUS_SUCCESS;
			}
		}
	}
	iosb->status = FILE_DOES_NOT_EXIST;
	iosb->status_info = 0;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	return STATUS_FAILURE;
}

STDCALL NTSTATUS WRAP_EXPORT(ZwReadFile)
	(void *handle, struct kevent *event, void *apc_routine,
	 void *apc_context, struct io_status_block *iosb, void *buffer,
	 ULONG length, LARGE_INTEGER *byte_offset, ULONG *key)
{
	struct object_attr *oa;
	ULONG count;
	struct ndis_bin_file *file;

	oa = HANDLE_TO_OBJECT(handle);
	file = oa->file;
	count = max(file->size - (ULONG)(*byte_offset), length);
	memcpy(buffer, file->data, file->size);
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(ZwClose)
	(void *handle)
{
	void *object = HANDLE_TO_OBJECT(handle);
	ObDereferenceObject(object);
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(ZwQueryInformationFile)
	(void *handle, struct io_status_block *iosb, void *info,
	 ULONG length, enum file_info_class class)
{
	struct object_attr *attr;
	struct file_name_info *fni;

	attr = HANDLE_TO_OBJECT(handle);
	switch (class) {
	case FileNameInformation:
		fni = info;
		fni->length = attr->name.len;
		memcpy(fni->name, attr->name.buf, attr->name.len);
		break;
	default:
		WARNING("type %d not implemented yet", class);
		return STATUS_FAILURE;
	}
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(WmiSystemControl)
	(struct wmilib_context *info, struct device_object *dev_obj,
	 struct irp *irp, void *irp_disposition)
{
	UNIMPL();
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(WmiCompleteRequest)
	(struct device_object *dev_obj, struct irp *irp, NTSTATUS status,
	 ULONG buffer_used, CCHAR priority_boost)
{
	UNIMPL();
	return STATUS_SUCCESS;
}

NOREGPARM NTSTATUS WRAP_EXPORT(WmiTraceMessage)
	(void *tracehandle, ULONG message_flags,
	 void *message_guid, USHORT message_no, ...)
{
	TRACEENTER2("%s", "");
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL NTSTATUS WRAP_EXPORT(WmiQueryTraceInformation)
	(enum trace_information_class trace_info_class, void *trace_info,
	 ULONG *req_length, void *buf)
{
	TRACEENTER2("%s", "");
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL unsigned int WRAP_EXPORT(IoWMIRegistrationControl)
	(struct device_object *dev_obj, ULONG action)
{
	TRACEENTER2("%s", "");
	TRACEEXIT2(return STATUS_SUCCESS);
}

/* this function can't be STDCALL as it takes variable number of args */
NOREGPARM ULONG WRAP_EXPORT(DbgPrint)
	(char *format, ...)
{
#ifdef DEBUG
	va_list args;
	static char buf[1024];

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	printk("DbgPrint: ");
	printk(buf);
	va_end(args);
#endif
	return STATUS_SUCCESS;
}

STDCALL void WRAP_EXPORT(KeBugCheckEx)
	(ULONG code, ULONG_PTR param1, ULONG_PTR param2,
	 ULONG_PTR param3, ULONG_PTR param4)
{
	UNIMPL();
	return;
}

STDCALL ULONG WRAP_EXPORT(ExSetTimerResolution)
	(ULONG time, BOOLEAN set)
{
	/* yet another "innovation"! */
	return time;
}


STDCALL void WRAP_EXPORT(DbgBreakPoint)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(_except_handler3)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(__C_specific_handler)(void){UNIMPL();}
void WRAP_EXPORT(_purecall)(void) { UNIMPL(); }

#include "ntoskernel_exports.h"
