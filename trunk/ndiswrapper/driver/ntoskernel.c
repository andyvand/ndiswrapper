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
#include "pnp.h"
#include "loader.h"

/* MDLs describe a range of virtual address with an array of physical
 * pages right after the header. For different ranges of virtual
 * addresses, the number of entries of physical pages may be different
 * (depending on number of entries required). If we want to allocate
 * MDLs from a pool, the size has to be constant. So we assume that
 * maximum range used by a driver is CACHE_MDL_PAGES; if a driver
 * requests an MDL for a bigger region, we allocate it with kmalloc;
 * otherwise, we allocate from the pool */

#define CACHE_MDL_PAGES 3
#define CACHE_MDL_SIZE (sizeof(struct mdl) + \
			(sizeof(PFN_NUMBER) * CACHE_MDL_PAGES))
struct wrap_mdl {
	struct nt_list list;
	char mdl[CACHE_MDL_SIZE];
};

struct thread_event_wait {
	wait_queue_head_t wq_head;
	BOOLEAN done;
#ifdef EVENT_DEBUG
	struct task_struct *task;
#endif
	struct thread_event_wait *next;
};

/* everything here is for all drivers/devices - not per driver/device */
static NT_SPIN_LOCK dispatcher_lock;
static struct thread_event_wait *thread_event_wait_pool;

NT_SPIN_LOCK ntoskernel_lock;
static kmem_cache_t *mdl_cache;
static struct nt_list wrap_mdl_list;

struct work_struct kdpc_work;
static struct nt_list kdpc_list;
static NT_SPIN_LOCK kdpc_list_lock;
static void kdpc_worker(void *data);

static struct nt_list callback_objects;

struct nt_list object_list;

struct bus_driver {
	struct nt_list list;
	char name[MAX_DRIVER_NAME_LEN];
	struct driver_object drv_obj;
};

static struct nt_list bus_driver_list;
static void del_bus_drivers(void);

static struct work_struct ntos_work_item_work;
static struct nt_list ntos_work_item_list;
static NT_SPIN_LOCK ntos_work_item_list_lock;
static void ntos_work_item_worker(void *data);

NT_SPIN_LOCK irp_cancel_lock;

extern NT_SPIN_LOCK loader_lock;
extern struct nt_list wrap_drivers;
static struct nt_list wrap_timer_list;
NT_SPIN_LOCK timer_lock;

/* compute ticks (100ns) since 1601 until when system booted into
 * wrap_ticks_to_boot */
u64 wrap_ticks_to_boot;

#if defined(CONFIG_X86_64)
static struct timer_list shared_data_timer;
struct kuser_shared_data kuser_shared_data;
static void update_user_shared_data_proc(unsigned long data);
#endif

static int add_bus_driver(const char *name);
static void free_all_objects(void);
static BOOLEAN queue_kdpc(struct kdpc *kdpc);
BOOLEAN dequeue_kdpc(struct kdpc *kdpc);

WRAP_EXPORT_MAP("KeTickCount", &jiffies);

WRAP_EXPORT_MAP("NlsMbCodePageTag", FALSE);

#ifdef USE_OWN_NTOS_WORKQUEUE
struct workqueue_struct *ntos_wq;
#endif

int ntoskernel_init(void)
{
	struct timeval now;

	nt_spin_lock_init(&dispatcher_lock);
	nt_spin_lock_init(&ntoskernel_lock);
	nt_spin_lock_init(&ntos_work_item_list_lock);
	nt_spin_lock_init(&kdpc_list_lock);
	nt_spin_lock_init(&irp_cancel_lock);
	InitializeListHead(&wrap_mdl_list);
	InitializeListHead(&kdpc_list);
	InitializeListHead(&callback_objects);
	InitializeListHead(&bus_driver_list);
	InitializeListHead(&object_list);
	InitializeListHead(&ntos_work_item_list);

	INIT_WORK(&kdpc_work, kdpc_worker, NULL);
	INIT_WORK(&ntos_work_item_work, ntos_work_item_worker, NULL);

	nt_spin_lock_init(&timer_lock);
	InitializeListHead(&wrap_timer_list);

	thread_event_wait_pool = NULL;
	do_gettimeofday(&now);
	wrap_ticks_to_boot = (u64)now.tv_sec * TICKSPERSEC;
	wrap_ticks_to_boot += now.tv_usec * 10;
	wrap_ticks_to_boot -= jiffies * TICKSPERSEC / HZ;
	wrap_ticks_to_boot += TICKS_1601_TO_1970;

#ifdef USE_OWN_NTOS_WORKQUEUE
	ntos_wq = create_singlethread_workqueue("ntos_wq");
#endif

	if (add_bus_driver("PCI")
#ifdef CONFIG_USB
	    || add_bus_driver("USB")
#endif
		) {
		ntoskernel_exit();
		return -ENOMEM;
	}
	mdl_cache = kmem_cache_create("wrap_mdl", sizeof(struct wrap_mdl),
				      0, 0, NULL, NULL);
	if (!mdl_cache) {
		ERROR("couldn't allocate MDL cache");
		ntoskernel_exit();
		return -ENOMEM;
	}
#if defined(CONFIG_X86_64)
	memset(&kuser_shared_data, 0, sizeof(kuser_shared_data));
	init_timer(&shared_data_timer);
	shared_data_timer.function = &update_user_shared_data_proc;
#endif
	return 0;
}

int ntoskernel_init_device(struct wrap_device *wd)
{
	InitializeListHead(&wd->timer_list);
#if defined(CONFIG_X86_64)
	*((ULONG64 *)&kuser_shared_data.system_time) = ticks_1601();
	shared_data_timer.data = (unsigned long)0;
	/* don't use add_timer - to avoid creating more than one
	 * timer */
	mod_timer(&shared_data_timer, jiffies + 1);
#endif
	return 0;
}

void ntoskernel_exit_device(struct wrap_device *wd)
{
	struct nt_list *ent;
	KIRQL irql;

	TRACEENTER2("");

	KeFlushQueuedDpcs();
	/* cancel any timers left by bugyy windows driver; also free
	 * the memory for timers */
	while (1) {
		struct wrap_timer *wrap_timer;

		irql = nt_spin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		ent = RemoveHeadList(&wd->timer_list);
		nt_spin_unlock_irql(&timer_lock, irql);
		if (!ent)
			break;
		wrap_timer = container_of(ent, struct wrap_timer, list);
		/* ktimer that this wrap_timer is associated to can't
		 * be touched, as it may have been freed by the driver
		 * already */
		if (del_timer_sync(&wrap_timer->timer))
			WARNING("Buggy Windows driver left timer %p running",
				&wrap_timer->timer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		slack_kfree(wrap_timer);
	}
	TRACEEXIT2(return);
}

void ntoskernel_exit(void)
{
	struct nt_list *cur;
	KIRQL irql;

	TRACEENTER2("");
	/* free kernel (Ke) timers */
	DBGTRACE2("freeing timers");
	while (1) {
		struct wrap_timer *wrap_timer;

		irql = nt_spin_lock_irql(&timer_lock, DISPATCH_LEVEL);
		cur = RemoveTailList(&wrap_timer_list);
		nt_spin_unlock_irql(&timer_lock, irql);
		if (!cur)
			break;
		wrap_timer = container_of(cur, struct wrap_timer, list);
		if (del_timer_sync(&wrap_timer->timer))
			WARNING("Buggy Windows driver left timer %p running",
				&wrap_timer->timer);
		memset(wrap_timer, 0, sizeof(*wrap_timer));
		slack_kfree(wrap_timer);
	}

	DBGTRACE2("freeing MDLs");
	if (mdl_cache) {
		irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
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
		nt_spin_unlock_irql(&ntoskernel_lock, irql);
		kmem_cache_destroy(mdl_cache);
		mdl_cache = NULL;
	}

	DBGTRACE2("freeing callbacks");
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
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
	nt_spin_unlock_irql(&ntoskernel_lock, irql);

	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	DBGTRACE2("freeing thread event pool");
	while (thread_event_wait_pool) {
		struct thread_event_wait *next;
		next = thread_event_wait_pool->next;
		kfree(thread_event_wait_pool);
		thread_event_wait_pool = next;
	}
	nt_spin_unlock_irql(&dispatcher_lock, irql);

	del_bus_drivers();
	free_all_objects();
#if defined(CONFIG_X86_64)
	del_timer_sync(&shared_data_timer);
#endif
#ifdef USE_OWN_NTOS_WORKQUEUE
	if (ntos_wq)
		destroy_workqueue(ntos_wq);
#endif
	TRACEEXIT2(return);
}

#if defined(CONFIG_X86_64)
static void update_user_shared_data_proc(unsigned long data)
{
	/* timer is supposed to be scheduled every 10ms, but bigger
	 * intervals seem to work (tried upto 50ms) */
	*((ULONG64 *)&kuser_shared_data.system_time) = ticks_1601();
	*((ULONG64 *)&kuser_shared_data.interrupt_time) =
		jiffies * TICKSPERSEC / HZ;
	*((ULONG64 *)&kuser_shared_data.tick) = jiffies;

	shared_data_timer.expires += 30 * HZ / 1000 + 1;
	add_timer(&shared_data_timer);
}
#endif

void *allocate_object(ULONG size, enum common_object_type type, char *name)
{
	struct common_object_header *hdr;
	void *body;
	KIRQL irql;

	/* we pad header as prefix to body */
	hdr = ExAllocatePoolWithTag(NonPagedPool, OBJECT_SIZE(size), 0);
	if (!hdr) {
		WARNING("couldn't allocate memory");
		return NULL;
	}
	memset(hdr, 0, OBJECT_SIZE(size));
	hdr->type = type;
	hdr->ref_count = 1;
	hdr->name = name;
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	/* threads are looked up often (in KeWaitForXXx), so optimize
	 * for fast lookups of threads */
	if (type == OBJECT_TYPE_NT_THREAD)
		InsertHeadList(&object_list, &hdr->list);
	else
		InsertTailList(&object_list, &hdr->list);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	body = HEADER_TO_OBJECT(hdr);
	DBGTRACE3("allocated hdr: %p, body: %p", hdr, body);
	return body;
}

void free_object(void *object)
{
	struct common_object_header *hdr;
	KIRQL irql;

	hdr = OBJECT_TO_HEADER(object);
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	RemoveEntryList(&hdr->list);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE3("freed hdr: %p, body: %p", hdr, object);
	ExFreePool(hdr);
}

static void free_all_objects(void)
{
	struct nt_list *cur;

	TRACEENTER2("freeing objects");
	/* delete all objects */
	while (1) {
		struct common_object_header *hdr;
		KIRQL irql;

		irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		cur = RemoveHeadList(&object_list);
		nt_spin_unlock_irql(&ntoskernel_lock, irql);
		if (!cur)
			break;
		hdr = container_of(cur, struct common_object_header, list);
		WARNING("object %p type %d was not freed, freeing it now",
			HEADER_TO_OBJECT(hdr), hdr->type);
		ExFreePool(hdr);
	}
	TRACEEXIT2(return);
}

static int add_bus_driver(const char *name)
{
	struct bus_driver *bus_driver;
	KIRQL irql;

	bus_driver = kmalloc(sizeof(*bus_driver), GFP_KERNEL);
	if (!bus_driver) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	memset(bus_driver, 0, sizeof(*bus_driver));
	strncpy(bus_driver->name, name, sizeof(bus_driver->name));
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	InsertTailList(&bus_driver_list, &bus_driver->list);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE1("bus driver %s is at %p", name, &bus_driver->drv_obj);
	return STATUS_SUCCESS;
}

static void del_bus_drivers(void)
{
	struct nt_list *ent;
	KIRQL irql;

	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((ent = RemoveHeadList(&bus_driver_list))) {
		struct bus_driver *bus_driver;
		bus_driver = container_of(ent, struct bus_driver, list);
		/* TODO: make sure all all drivers are shutdown/removed */
		kfree(bus_driver);
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
}

struct driver_object *find_bus_driver(const char *name)
{
	struct bus_driver *bus_driver;
	struct driver_object *drv_obj;
	KIRQL irql;

	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	drv_obj = NULL;
	nt_list_for_each_entry(bus_driver, &bus_driver_list, list) {
		if (strcmp(bus_driver->name, name) == 0)
			drv_obj = &bus_driver->drv_obj;
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	return drv_obj;
}

wfastcall struct nt_list *WRAP_EXPORT(ExfInterlockedInsertHeadList)
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock)
{
	struct nt_list *first;
	unsigned long flags;

	TRACEENTER5("head = %p, entry = %p", head, entry);
	nt_spin_lock_irqsave(lock, flags);
	first = InsertHeadList(head, entry);
	nt_spin_unlock_irqrestore(lock, flags);
	DBGTRACE5("head = %p, old = %p", head, first);
	return first;
}

wfastcall struct nt_list *WRAP_EXPORT(ExInterlockedInsertHeadList)
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock)
{
	TRACEENTER5("%p", head);
	return ExfInterlockedInsertHeadList(head, entry, lock);
}

wfastcall struct nt_list *WRAP_EXPORT(ExfInterlockedInsertTailList)
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock)
{
	struct nt_list *last;
	unsigned long flags;

	TRACEENTER5("head = %p, entry = %p", head, entry);
	nt_spin_lock_irqsave(lock, flags);
	last = InsertTailList(head, entry);
	nt_spin_unlock_irqrestore(lock, flags);
	DBGTRACE5("head = %p, old = %p", head, last);
	return last;
}

wfastcall struct nt_list *WRAP_EXPORT(ExInterlockedInsertTailList)
	(struct nt_list *head, struct nt_list *entry, NT_SPIN_LOCK *lock)
{
	TRACEENTER5("%p", head);
	return ExfInterlockedInsertTailList(head, entry, lock);
}

wfastcall struct nt_list *WRAP_EXPORT(ExfInterlockedRemoveHeadList)
	(struct nt_list *head, NT_SPIN_LOCK *lock)
{
	struct nt_list *ret;
	unsigned long flags;

	TRACEENTER5("head = %p", head);
	nt_spin_lock_irqsave(lock, flags);
	ret = RemoveHeadList(head);
	nt_spin_unlock_irqrestore(lock, flags);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wfastcall struct nt_list *WRAP_EXPORT(ExInterlockedRemoveHeadList)
	(struct nt_list *head, NT_SPIN_LOCK *lock)
{
	TRACEENTER5("%p", head);
	return ExfInterlockedRemoveHeadList(head, lock);
}

wfastcall struct nt_list *WRAP_EXPORT(ExfInterlockedRemoveTailList)
	(struct nt_list *head, NT_SPIN_LOCK *lock)
{
	struct nt_list *ret;
	unsigned long flags;

	TRACEENTER5("head = %p", head);
	nt_spin_lock_irqsave(lock, flags);
	ret = RemoveTailList(head);
	nt_spin_unlock_irqrestore(lock, flags);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wfastcall struct nt_list *WRAP_EXPORT(ExInterlockedRemoveTailList)
	(struct nt_list *head, NT_SPIN_LOCK *lock)
{
	TRACEENTER5("%p", head);
	return ExfInterlockedRemoveTailList(head, lock);
}

wfastcall struct nt_slist *WRAP_EXPORT(ExInterlockedPushEntrySList)
	(nt_slist_header *head, struct nt_slist *entry, NT_SPIN_LOCK *lock)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PushEntrySList(head, entry, lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wstdcall struct nt_slist *WRAP_EXPORT(ExpInterlockedPushEntrySList)
	(nt_slist_header *head, struct nt_slist *entry)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PushEntrySList(head, entry, &ntoskernel_lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wfastcall struct nt_slist *WRAP_EXPORT(InterlockedPushEntrySList)
	(nt_slist_header *head, struct nt_slist *entry)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PushEntrySList(head, entry, &ntoskernel_lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wfastcall struct nt_slist *WRAP_EXPORT(ExInterlockedPopEntrySList)
	(nt_slist_header *head, NT_SPIN_LOCK *lock)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PopEntrySList(head, lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wstdcall struct nt_slist *WRAP_EXPORT(ExpInterlockedPopEntrySList)
	(nt_slist_header *head)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PopEntrySList(head, &ntoskernel_lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wfastcall struct nt_slist *WRAP_EXPORT(InterlockedPopEntrySList)
	(nt_slist_header *head)
{
	struct nt_slist *ret;

	TRACEENTER5("head = %p", head);
	ret = PopEntrySList(head, &ntoskernel_lock);
	DBGTRACE5("head = %p, ret = %p", head, ret);
	return ret;
}

wstdcall USHORT WRAP_EXPORT(ExQueryDepthSList)
	(nt_slist_header *head)
{
	USHORT depth;
	TRACEENTER5("%p", head);
#ifdef CONFIG_X86_64
	depth = head->align & 0xffff;
	DBGTRACE5("%d, %Lx", depth, head->region);
#else
	depth = head->depth;
#endif
	return depth;
}

wfastcall LONG WRAP_EXPORT(InterlockedIncrement)
	(LONG volatile *val)
{
	return post_atomic_add(*val, 1);
}

wfastcall LONG WRAP_EXPORT(InterlockedDecrement)
	(LONG volatile *val)
{
	return post_atomic_add(*val, -1);
}

wfastcall LONG WRAP_EXPORT(InterlockedExchange)
	(LONG volatile *target, LONG val)
{
	return xchg(target, val);
}

wfastcall LONG WRAP_EXPORT(InterlockedCompareExchange)
	(LONG volatile *dest, LONG new, LONG old)
{
	return cmpxchg(dest, old, new);
}

wfastcall void WRAP_EXPORT(ExInterlockedAddLargeStatistic)
	(LARGE_INTEGER volatile *plint, ULONG n)
{
	unsigned long flags;
	save_local_irq(flags);
#ifdef CONFIG_X86_64
	__asm__ __volatile__(
		"\n"
		LOCK_PREFIX "add %0, %1\n\t"
		:
		: "r" (n), "m" (*plint)
		: "memory");
#else
	__asm__ __volatile__(
		"\n"
		"1:\t"
		"   movl %1, %%ebx\n\t"
		"   movl %%edx, %%ecx\n\t"
		"   addl %%eax, %%ebx\n\t"
		"   adcl $0, %%ecx\n\t"
		    LOCK_PREFIX "cmpxchg8b (%0)\n\t"
		"   jnz 1b\n\t"
		: "+r" (plint)
		: "m" (n), "a" (ll_low(*plint)), "d" (ll_high(*plint))
		: "ebx", "ecx", "cc", "memory");
#endif
	restore_local_irq(flags);
}

/* should be called with dispatcher_lock held at DISPATCH_LEVEL */
static void initialize_dh(struct dispatcher_header *dh, enum dh_type type,
			  int state)
{
	memset(dh, 0, sizeof(*dh));
	set_dh_type(dh, type);
	dh->signal_state = state;
	InitializeListHead(&dh->wait_blocks);
}

static void timer_proc(unsigned long data)
{
	struct nt_timer *nt_timer = (struct nt_timer *)data;
	struct wrap_timer *wrap_timer;
	struct kdpc *kdpc;

	wrap_timer = nt_timer->wrap_timer;
	TRACEENTER5("%p(%p), %lu", wrap_timer, nt_timer, jiffies);
#ifdef DEBUG_TIMER
	BUG_ON(wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC);
	BUG_ON(nt_timer->wrap_timer_magic != WRAP_TIMER_MAGIC);
#endif
	KeSetEvent((struct nt_event *)nt_timer, 0, FALSE);

	kdpc = nt_timer->kdpc;
	if (kdpc && kdpc->func) {
		/* nmb is set for NDIS timers of serialized drivers only */
		if (wrap_timer->nmb)
			nt_spin_lock(&wrap_timer->nmb->lock);
//		queue_kdpc(kdpc);
		LIN2WIN4(kdpc->func, kdpc, kdpc->ctx, kdpc->arg1, kdpc->arg2);
		if (wrap_timer->nmb)
			nt_spin_unlock(&wrap_timer->nmb->lock);
	}

	nt_spin_lock(&timer_lock);
	if (wrap_timer->repeat)
		mod_timer(&wrap_timer->timer, jiffies + wrap_timer->repeat);
	nt_spin_unlock(&timer_lock);
	TRACEEXIT5(return);
}

void wrap_init_timer(struct nt_timer *nt_timer, enum timer_type type,
		     struct ndis_miniport_block *nmb)
{
	struct wrap_timer *wrap_timer;
	KIRQL irql;

	/* TODO: if a timer is initialized more than once, we allocate
	 * memory for wrap_timer more than once for the same nt_timer,
	 * wasting memory. We can check if nt_timer->wrap_timer_magic is
	 * set and not allocate, but it is not guaranteed always to be
	 * safe */
	TRACEENTER5("%p", nt_timer);
	/* we allocate memory for wrap_timer behind driver's back and
	 * there is no NDIS/DDK function where this memory can be
	 * freed, so we use slack_kmalloc so it gets freed when driver
	 * is unloaded */
	wrap_timer = slack_kmalloc(sizeof(*wrap_timer));
	if (!wrap_timer) {
		ERROR("couldn't allocate memory for timer");
		return;
	}

	memset(wrap_timer, 0, sizeof(*wrap_timer));
	init_timer(&wrap_timer->timer);
	wrap_timer->timer.data = (unsigned long)nt_timer;
	wrap_timer->timer.function = timer_proc;
	wrap_timer->nt_timer = nt_timer;
#ifdef DEBUG_TIMER
	wrap_timer->wrap_timer_magic = WRAP_TIMER_MAGIC;
#endif
	nt_timer->wrap_timer = wrap_timer;
	nt_timer->kdpc = NULL;
	initialize_dh(&nt_timer->dh, type, 0);
	nt_timer->wrap_timer_magic = WRAP_TIMER_MAGIC;
	irql = nt_spin_lock_irql(&timer_lock, DISPATCH_LEVEL);
	if (nmb)
		InsertTailList(&nmb->wnd->wd->timer_list, &wrap_timer->list);
	else
		InsertTailList(&wrap_timer_list, &wrap_timer->list);
	nt_spin_unlock_irql(&timer_lock, irql);
	if (nmb && !deserialized_driver(nmb->wnd))
		wrap_timer->nmb = nmb;
	else
		wrap_timer->nmb = NULL;
	DBGTRACE5("timer %p (%p)", wrap_timer, nt_timer);
	TRACEEXIT5(return);
}

wstdcall void WRAP_EXPORT(KeInitializeTimerEx)
	(struct nt_timer *nt_timer, enum timer_type type)
{
	TRACEENTER5("%p", nt_timer);
	wrap_init_timer(nt_timer, type, NULL);
}

wstdcall void WRAP_EXPORT(KeInitializeTimer)
	(struct nt_timer *nt_timer)
{
	TRACEENTER5("%p", nt_timer);
	wrap_init_timer(nt_timer, NotificationTimer, NULL);
}

/* expires and repeat are in HZ */
BOOLEAN wrap_set_timer(struct nt_timer *nt_timer, unsigned long expires_hz,
		       unsigned long repeat_hz, struct kdpc *kdpc)
{
	BOOLEAN ret;
	struct wrap_timer *wrap_timer;
	KIRQL irql;

	TRACEENTER4("%p, %lu, %lu, %p, %lu",
		    nt_timer, expires_hz, repeat_hz, kdpc, jiffies);

	KeClearEvent((struct nt_event *)nt_timer);
	wrap_timer = nt_timer->wrap_timer;

#ifdef DEBUG_TIMER
	if (nt_timer->wrap_timer_magic != WRAP_TIMER_MAGIC) {
		WARNING("Buggy Windows timer didn't initialize timer %p",
			nt_timer);
		return FALSE;
	}
	if (wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC) {
		WARNING("timer %p is not initialized (%lx)?",
			wrap_timer, wrap_timer->wrap_timer_magic);
		wrap_timer->wrap_timer_magic = WRAP_TIMER_MAGIC;
	}
#endif
	irql = nt_spin_lock_irql(&timer_lock, DISPATCH_LEVEL);
	if (kdpc)
		nt_timer->kdpc = kdpc;
	wrap_timer->repeat = repeat_hz;
	nt_spin_unlock_irql(&timer_lock, irql);
	if (mod_timer(&wrap_timer->timer, jiffies + expires_hz))
		ret = TRUE;
	else
		ret = FALSE;

	TRACEEXIT5(return ret);
}

wstdcall BOOLEAN WRAP_EXPORT(KeSetTimerEx)
	(struct nt_timer *nt_timer, LARGE_INTEGER duetime_ticks,
	 LONG period_ms, struct kdpc *kdpc)
{
	unsigned long expires_hz, repeat_hz;

	DBGTRACE5("%p, %Ld, %d", nt_timer, duetime_ticks, period_ms);
	expires_hz = SYSTEM_TIME_TO_HZ(duetime_ticks) + 1;
	repeat_hz = MSEC_TO_HZ(period_ms);
	return wrap_set_timer(nt_timer, expires_hz, repeat_hz, kdpc);
}

wstdcall BOOLEAN WRAP_EXPORT(KeSetTimer)
	(struct nt_timer *nt_timer, LARGE_INTEGER duetime_ticks,
	 struct kdpc *kdpc)
{
	TRACEENTER5("%p, %Ld, %p", nt_timer, duetime_ticks, kdpc);
	return KeSetTimerEx(nt_timer, duetime_ticks, 0, kdpc);
}

wstdcall BOOLEAN WRAP_EXPORT(KeCancelTimer)
	(struct nt_timer *nt_timer)
{
	BOOLEAN canceled;
	struct wrap_timer *wrap_timer;

	TRACEENTER5("%p", nt_timer);
	wrap_timer = nt_timer->wrap_timer;
	if (!wrap_timer) {
		ERROR("invalid wrap_timer");
		return TRUE;
	}
#ifdef DEBUG_TIMER
	DBGTRACE5("canceling timer %p", wrap_timer);
	BUG_ON(wrap_timer->wrap_timer_magic != WRAP_TIMER_MAGIC);
#endif
	/* del_timer_sync may not be called here, as this function can
	 * be called at DISPATCH_LEVEL */
	nt_spin_lock(&timer_lock);
	DBGTRACE5("deleting timer %p(%p)", wrap_timer, nt_timer);
	/* disable timer before deleting so it won't be re-armed after
	 * deleting */
	wrap_timer->repeat = 0;
	if (del_timer(&wrap_timer->timer))
		canceled = TRUE;
	else
		canceled = FALSE;
	nt_spin_unlock(&timer_lock);
	DBGTRACE5("canceled (%p): %d", wrap_timer, canceled);
	TRACEEXIT5(return canceled);
}

wstdcall void WRAP_EXPORT(KeInitializeDpc)
	(struct kdpc *kdpc, void *func, void *ctx)
{
	TRACEENTER3("%p, %p, %p", kdpc, func, ctx);
	memset(kdpc, 0, sizeof(*kdpc));
	kdpc->nr_cpu = FALSE;
	kdpc->func = func;
	kdpc->ctx  = ctx;
	InitializeListHead(&kdpc->list);
}

static void kdpc_worker(void *data)
{
	struct nt_list *entry;
	struct kdpc *kdpc;
	KIRQL irql;

	while (1) {
		irql = nt_spin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
		entry = RemoveHeadList(&kdpc_list);
		if (!entry) {
			nt_spin_unlock_irql(&kdpc_list_lock, irql);
			break;
		}
		kdpc = container_of(entry, struct kdpc, list);
		kdpc->nr_cpu = FALSE;
		nt_spin_unlock_irql(&kdpc_list_lock, irql);
		DBGTRACE5("%p, %p, %p, %p, %p", kdpc, kdpc->func, kdpc->ctx,
			  kdpc->arg1, kdpc->arg2);
		irql = raise_irql(DISPATCH_LEVEL);
		LIN2WIN4(kdpc->func, kdpc, kdpc->ctx, kdpc->arg1, kdpc->arg2);
		lower_irql(irql);
	}
}

wstdcall void KeFlushQueuedDpcs(void)
{
	kdpc_worker(NULL);
}

static BOOLEAN queue_kdpc(struct kdpc *kdpc)
{
	BOOLEAN ret;
	KIRQL irql;

	TRACEENTER5("%p", kdpc);
	if (!kdpc)
		return FALSE;
	irql = nt_spin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
	if (kdpc->nr_cpu) {
		if (kdpc->nr_cpu != TRUE)
			ERROR("kdpc->nr_cpu: %d", kdpc->nr_cpu);
		ret = FALSE;
	} else {
		ret = kdpc->nr_cpu = TRUE;
		InsertTailList(&kdpc_list, &kdpc->list);
		schedule_ntos_work(&kdpc_work);
	}
	nt_spin_unlock_irql(&kdpc_list_lock, irql);
	TRACEEXIT5(return ret);
}

BOOLEAN dequeue_kdpc(struct kdpc *kdpc)
{
	BOOLEAN ret;
	KIRQL irql;

	TRACEENTER5("%p", kdpc);
	if (!kdpc)
		return FALSE;
	irql = nt_spin_lock_irql(&kdpc_list_lock, DISPATCH_LEVEL);
	if (kdpc->nr_cpu) {
		if (kdpc->nr_cpu != TRUE)
			ERROR("kdpc->nr_cpu: %d", kdpc->nr_cpu);
		kdpc->nr_cpu = FALSE;
		RemoveEntryList(&kdpc->list);
		ret = TRUE;
	} else
		ret = FALSE;
	nt_spin_unlock_irql(&kdpc_list_lock, irql);
	return ret;
}

wstdcall BOOLEAN WRAP_EXPORT(KeInsertQueueDpc)
	(struct kdpc *kdpc, void *arg1, void *arg2)
{
	BOOLEAN ret;

	TRACEENTER5("%p, %p, %p", kdpc, arg1, arg2);
	kdpc->arg1 = arg1;
	kdpc->arg2 = arg2;
	ret = queue_kdpc(kdpc);
	TRACEEXIT5(return ret);
}

wstdcall BOOLEAN WRAP_EXPORT(KeRemoveQueueDpc)
	(struct kdpc *kdpc)
{
	BOOLEAN ret;

	TRACEENTER3("%p", kdpc);
	ret = dequeue_kdpc(kdpc);
	TRACEEXIT3(return ret);
}

static void ntos_work_item_worker(void *data)
{
	struct ntos_work_item *ntos_work_item;
	struct nt_list *cur;
	typeof(ntos_work_item->func) func;
	KIRQL irql;

	while (1) {
		irql = nt_spin_lock_irql(&ntos_work_item_list_lock,
					 DISPATCH_LEVEL);
		cur = RemoveHeadList(&ntos_work_item_list);
		nt_spin_unlock_irql(&ntos_work_item_list_lock, irql);
		if (!cur)
			break;
		ntos_work_item = container_of(cur, struct ntos_work_item, list);
		func = ntos_work_item->func;
		WORKTRACE("%p: executing %p, %p, %p", current, func,
			  ntos_work_item->arg1, ntos_work_item->arg2);
		if (ntos_work_item->func_type == WORKER_FUNC_WIN)
			LIN2WIN2(func, ntos_work_item->arg1,
				 ntos_work_item->arg2);
		else
			func(ntos_work_item->arg1, ntos_work_item->arg2);
		kfree(ntos_work_item);
	}
	return;
}

int schedule_ntos_work_item(NTOS_WORK_FUNC func, void *arg1, void *arg2,
			    enum worker_func_type func_type)
{
	struct ntos_work_item *ntos_work_item;
	KIRQL irql;

	WORKENTER("adding work: %p, %p, %p", func, arg1, arg2);
	ntos_work_item = kmalloc(sizeof(*ntos_work_item), GFP_ATOMIC);
	if (!ntos_work_item) {
		ERROR("couldn't allocate memory");
		return -ENOMEM;
	}
	ntos_work_item->func = func;
	ntos_work_item->arg1 = arg1;
	ntos_work_item->arg2 = arg2;
	ntos_work_item->func_type = func_type;
	irql = nt_spin_lock_irql(&ntos_work_item_list_lock, DISPATCH_LEVEL);
	InsertTailList(&ntos_work_item_list, &ntos_work_item->list);
	nt_spin_unlock_irql(&ntos_work_item_list_lock, irql);
	schedule_ntos_work(&ntos_work_item_work);
	WORKEXIT(return 0);
}

wstdcall void WRAP_EXPORT(KeInitializeSpinLock)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	nt_spin_lock_init(lock);
}

wstdcall void WRAP_EXPORT(KeAcquireSpinLock)
	(NT_SPIN_LOCK *lock, KIRQL *irql)
{
	TRACEENTER6("%p", lock);
	*irql = nt_spin_lock_irql(lock, DISPATCH_LEVEL);
}

wstdcall void WRAP_EXPORT(KeReleaseSpinLock)
	(NT_SPIN_LOCK *lock, KIRQL oldirql)
{
	TRACEENTER6("%p", lock);
	nt_spin_unlock_irql(lock, oldirql);
	DBGTRACE5("%d, %d", oldirql, current_irql());
}

wstdcall void WRAP_EXPORT(KeAcquireSpinLockAtDpcLevel)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	nt_spin_lock(lock);
}

wstdcall void WRAP_EXPORT(KeReleaseSpinLockFromDpcLevel)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	nt_spin_unlock(lock);
}

wstdcall void WRAP_EXPORT(KeRaiseIrql)
	(KIRQL newirql, KIRQL *oldirql)
{
	TRACEENTER6("%d", newirql);
	*oldirql = raise_irql(newirql);
}

wstdcall KIRQL WRAP_EXPORT(KeRaiseIrqlToDpcLevel)
	(void)
{
	return raise_irql(DISPATCH_LEVEL);
}

wstdcall void WRAP_EXPORT(KeLowerIrql)
	(KIRQL irql)
{
	TRACEENTER6("%d", irql);
	lower_irql(irql);
}

wstdcall KIRQL WRAP_EXPORT(KeAcquireSpinLockRaiseToDpc)
	(NT_SPIN_LOCK *lock)
{
	TRACEENTER6("%p", lock);
	return nt_spin_lock_irql(lock, DISPATCH_LEVEL);
}

#undef ExAllocatePoolWithTag

wstdcall void *WRAP_EXPORT(ExAllocatePoolWithTag)
	(enum pool_type pool_type, SIZE_T size, ULONG tag)
{
	void *addr;

	TRACEENTER4("pool_type: %d, size: %lu, tag: %u", pool_type,
		    size, tag);
	if (size <= KMALLOC_THRESHOLD) {
		if (current_irql() < DISPATCH_LEVEL)
			addr = kmalloc(size, GFP_KERNEL);
		else
			addr = kmalloc(size, GFP_ATOMIC);
	} else {
		if (current_irql() < DISPATCH_LEVEL)
			addr = vmalloc(size);
		else
			addr = __vmalloc(size, GFP_ATOMIC | __GFP_HIGHMEM,
					 PAGE_KERNEL);
	}
	DBGTRACE4("addr: %p, %lu", addr, size);
	TRACEEXIT4(return addr);
}

static wstdcall void vfree_nonatomic(void *addr, void *ctx)
{
	vfree(addr);
}

wstdcall void WRAP_EXPORT(ExFreePool)
	(void *addr)
{
	DBGTRACE4("addr: %p", addr);
	if ((unsigned long)addr < VMALLOC_START ||
	    (unsigned long)addr >= VMALLOC_END)
		kfree(addr);
	else {
		if (in_interrupt())
			schedule_ntos_work_item(vfree_nonatomic, addr,
						NULL, WORKER_FUNC_LINUX);
		else
			vfree(addr);
	}
	TRACEEXIT4(return);
}

wstdcall void WRAP_EXPORT(ExFreePoolWithTag)
	(void *addr, ULONG tag)
{
	ExFreePool(addr);
}

WRAP_FUNC_PTR_DECL(ExAllocatePoolWithTag)
WRAP_FUNC_PTR_DECL(ExFreePool)

wstdcall void WRAP_EXPORT(ExInitializeNPagedLookasideList)
	(struct npaged_lookaside_list *lookaside,
	 LOOKASIDE_ALLOC_FUNC *alloc_func, LOOKASIDE_FREE_FUNC *free_func,
	 ULONG flags, SIZE_T size, ULONG tag, USHORT depth)
{
	TRACEENTER3("lookaside: %p, size: %lu, flags: %u, head: %p, "
		    "alloc: %p, free: %p", lookaside, size, flags,
		    lookaside, alloc_func, free_func);

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

#ifndef CONFIG_X86_64
	DBGTRACE3("lock: %p", &lookaside->obsolete);
	nt_spin_lock_init(&lookaside->obsolete);
#endif
	TRACEEXIT3(return);
}

wstdcall void WRAP_EXPORT(ExDeleteNPagedLookasideList)
	(struct npaged_lookaside_list *lookaside)
{
	struct nt_slist *entry;
	KIRQL irql;

	TRACEENTER3("lookaside = %p", lookaside);
	irql = raise_irql(DISPATCH_LEVEL);
	while ((entry = ExpInterlockedPopEntrySList(&lookaside->head))) {
		if (lookaside->free_func == (LOOKASIDE_FREE_FUNC *)
		    WRAP_FUNC_PTR(ExFreePool))
			ExFreePool(entry);
		else
			LIN2WIN1(lookaside->free_func, entry);
	}
	lower_irql(irql);
	TRACEEXIT3(return);
}

#if defined(ALLOC_DEBUG) && ALLOC_DEBUG > 1
#define ExAllocatePoolWithTag(pool_type, size, tag)			\
	wrap_ExAllocatePoolWithTag(pool_type, size, tag, __FILE__, __LINE__)
#endif

wstdcall NTSTATUS WRAP_EXPORT(ExCreateCallback)
	(struct callback_object **object, struct object_attributes *attributes,
	 BOOLEAN create, BOOLEAN allow_multiple_callbacks)
{
	struct callback_object *obj;
	KIRQL irql;

	TRACEENTER2("");
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(obj, &callback_objects, callback_funcs) {
		if (obj->attributes == attributes) {
			nt_spin_unlock_irql(&ntoskernel_lock, irql);
			*object = obj;
			return STATUS_SUCCESS;
		}
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	obj = allocate_object(sizeof(struct callback_object),
			      OBJECT_TYPE_CALLBACK, NULL);
	if (!obj)
		TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
	InitializeListHead(&obj->callback_funcs);
	nt_spin_lock_init(&obj->lock);
	obj->allow_multiple_callbacks = allow_multiple_callbacks;
	obj->attributes = attributes;
	*object = obj;
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall void *WRAP_EXPORT(ExRegisterCallback)
	(struct callback_object *object, PCALLBACK_FUNCTION func,
	 void *context)
{
	struct callback_func *callback;
	KIRQL irql;

	TRACEENTER2("");
	irql = nt_spin_lock_irql(&object->lock, DISPATCH_LEVEL);
	if (object->allow_multiple_callbacks == FALSE &&
	    !IsListEmpty(&object->callback_funcs)) {
		nt_spin_unlock_irql(&object->lock, irql);
		TRACEEXIT2(return NULL);
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	callback = kmalloc(sizeof(*callback), GFP_KERNEL);
	if (!callback) {
		ERROR("couldn't allocate memory");
		return NULL;
	}
	callback->func = func;
	callback->context = context;
	callback->object = object;
	irql = nt_spin_lock_irql(&object->lock, DISPATCH_LEVEL);
	InsertTailList(&object->callback_funcs, &callback->list);
	nt_spin_unlock_irql(&object->lock, irql);
	TRACEEXIT2(return callback);
}

wstdcall void WRAP_EXPORT(ExUnregisterCallback)
	(struct callback_func *callback)
{
	struct callback_object *object;
	KIRQL irql;

	TRACEENTER3("%p", callback);
	if (!callback)
		return;
	object = callback->object;
	irql = nt_spin_lock_irql(&object->lock, DISPATCH_LEVEL);
	RemoveEntryList(&callback->list);
	nt_spin_unlock_irql(&object->lock, irql);
	kfree(callback);
	return;
}

wstdcall void WRAP_EXPORT(ExNotifyCallback)
	(struct callback_object *object, void *arg1, void *arg2)
{
	struct callback_func *callback;
	KIRQL irql;

	TRACEENTER3("%p", object);
	irql = nt_spin_lock_irql(&object->lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(callback, &object->callback_funcs, list){
		LIN2WIN3(callback->func, callback->context, arg1, arg2);
	}
	nt_spin_unlock_irql(&object->lock, irql);
	return;
}

/* check and set signaled state; should be called with dispatcher_lock held */
/* @grab indicates if the event should be put in not-signaled state
 * - note that a semaphore may stay in signaled state for multiple
 * 'grabs' if the count is > 1 */
static int check_grab_signaled_state(struct dispatcher_header *dh,
				     struct task_struct *thread, int grab)
{
	EVENTTRACE("%p, %p, %d, %d", dh, thread, grab, dh->signal_state);
	if (is_mutex_dh(dh)) {
		struct nt_mutex *nt_mutex;
		/* either no thread owns the mutex or this thread owns
		 * it */
		nt_mutex = container_of(dh, struct nt_mutex, dh);
		EVENTTRACE("%p, %p", nt_mutex, nt_mutex->owner_thread);
		assert(dh->signal_state <= 1);
		assert(nt_mutex->owner_thread == NULL &&
		       dh->signal_state == 1);
		if (dh->signal_state > 0 || nt_mutex->owner_thread == thread) {
			if (grab) {
				dh->signal_state--;
				nt_mutex->owner_thread = thread;
			}
			EVENTEXIT(return 1);
		}
	} else if (dh->signal_state > 0) {
		/* if grab, decrement signal_state for
		 * synchronization or semaphore objects */
		if (grab && (dh->type == SynchronizationObject ||
			     is_semaphore_dh(dh)))
			dh->signal_state--;
		EVENTEXIT(return 1);
	}
	EVENTEXIT(return 0);
}

/* this function should be called holding dispatcher_lock spinlock at
 * DISPATCH_LEVEL */
static void wakeup_threads(struct dispatcher_header *dh)
{
	struct nt_list *cur, *next;
	struct wait_block *wb = NULL;

	nt_list_for_each_safe(cur, next, &dh->wait_blocks) {
		wb = container_of(cur, struct wait_block, list);
		EVENTTRACE("%p: wait block: %p, thread: %p",
			   dh, wb, wb->thread);
		assert(wb->thread != NULL);
		assert(wb->object == NULL);
		if (wb->thread &&
		    check_grab_signaled_state(dh, wb->thread, 1)) {
			struct thread_event_wait *thread_wait = wb->thread_wait;
			EVENTTRACE("%p: waking up task %p for %p", thread_wait,
				   wb->thread, dh);
			RemoveEntryList(&wb->list);
			wb->object = dh;
			thread_wait->done = 1;
			wake_up(&thread_wait->wq_head);
			if (dh->type == SynchronizationObject)
				break;
		} else
			EVENTTRACE("not waking up task: %p", wb->thread);
	}
	EVENTEXIT(return);
}

/* We need workqueue to implement KeWaitFor routines
 * below. (get/put)_thread_event_wait give/take back a workqueue. Both
 * these are called holding dispatcher spinlock, so no locking here */
static inline struct thread_event_wait *get_thread_event_wait(void)
{
	struct thread_event_wait *thread_event_wait;

	if (thread_event_wait_pool) {
		thread_event_wait = thread_event_wait_pool;
		thread_event_wait_pool = thread_event_wait_pool->next;
	} else {
		thread_event_wait = kmalloc(sizeof(*thread_event_wait),
					    GFP_ATOMIC);
		if (!thread_event_wait) {
			WARNING("couldn't allocate memory");
			return NULL;
		}
		EVENTTRACE("allocated wq: %p", thread_event_wait);
		init_waitqueue_head(&thread_event_wait->wq_head);
	}
#ifdef EVENT_DEBUG
	thread_event_wait->task = current;
#endif
	EVENTTRACE("%p, %p, %p", thread_event_wait, current,
		   thread_event_wait_pool);
	thread_event_wait->done = 0;
	return thread_event_wait;
}

static void put_thread_event_wait(struct thread_event_wait *thread_event_wait)
{
	EVENTENTER("%p, %p", thread_event_wait, current);
#ifdef EVENT_DEBUG
	if (thread_event_wait->task != current)
		ERROR("argh, task %p should be %p",
		      current, thread_event_wait->task);
	thread_event_wait->task = NULL;
#endif
	thread_event_wait->next = thread_event_wait_pool;
	thread_event_wait_pool = thread_event_wait;
	thread_event_wait->done = 0;
}

wstdcall NTSTATUS WRAP_EXPORT(KeWaitForMultipleObjects)
	(ULONG count, void *object[], enum wait_type wait_type,
	 KWAIT_REASON wait_reason, KPROCESSOR_MODE wait_mode,
	 BOOLEAN alertable, LARGE_INTEGER *timeout,
	 struct wait_block *wait_block_array)
{
	int i, res = 0, wait_count;
	long wait_jiffies = 0;
	struct wait_block *wb, wb_array[THREAD_WAIT_OBJECTS];
	struct dispatcher_header *dh;
	struct task_struct *thread;
	struct thread_event_wait *thread_wait;
	KIRQL irql;

	thread = current;
	EVENTTRACE("thread: %p count = %d, type: %d, reason = %u, "
		   "waitmode = %u, alertable = %u, timeout = %p", thread,
		   count, wait_type, wait_reason, wait_mode, alertable,
		   timeout);

	if (count > MAX_WAIT_OBJECTS)
		EVENTEXIT(return STATUS_INVALID_PARAMETER);
	if (count > THREAD_WAIT_OBJECTS && wait_block_array == NULL)
		EVENTEXIT(return STATUS_INVALID_PARAMETER);

	if (wait_block_array == NULL)
		wb = &wb_array[0];
	else
		wb = wait_block_array;

	/* TODO: should we allow threads to wait in non-alertable state? */
	alertable = TRUE;
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	/* If *timeout == 0: In the case of WaitAny, if an object can
	 * be grabbed (object is in signaled state), grab and
	 * return. In the case of WaitAll, we have to first make sure
	 * all objects can be grabbed. If any/some of them can't be
	 * grabbed, either we return STATUS_TIMEOUT or wait for them,
	 * depending on how to satisfy wait. If all of them can be
	 * grabbed, we will grab them in the next loop below */

	for (i = wait_count = 0; i < count; i++) {
		dh = object[i];
		EVENTTRACE("%p: event %p state: %d",
			   thread, dh, dh->signal_state);
		/* wait_type == 1 for WaitAny, 0 for WaitAll */
		if (check_grab_signaled_state(dh, thread, wait_type)) {
			if (wait_type == WaitAny) {
				nt_spin_unlock_irql(&dispatcher_lock, irql);
				if (count > 1)
					EVENTEXIT(return STATUS_WAIT_0 + i);
				else
					EVENTEXIT(return STATUS_SUCCESS);
			}
		} else {
			EVENTTRACE("%p: wait for %p", thread, dh);
			wait_count++;
		}
	}

	if (wait_count) {
		if (timeout && *timeout == 0) {
			nt_spin_unlock_irql(&dispatcher_lock, irql);
			EVENTEXIT(return STATUS_TIMEOUT);
		}
		thread_wait = get_thread_event_wait();
		if (!thread_wait) {
			nt_spin_unlock_irql(&dispatcher_lock, irql);
			EVENTEXIT(return STATUS_RESOURCES);
		}
	} else
		thread_wait = NULL;

	/* get the list of objects the thread needs to wait on and add
	 * the thread on the wait list for each such object */
	/* if *timeout == 0, this step will grab all the objects */
	for (i = 0; i < count; i++) {
		dh = object[i];
		EVENTTRACE("%p: event %p state: %d",
			   thread, dh, dh->signal_state);
		wb[i].object = NULL;
		wb[i].thread_wait = thread_wait;
		if (check_grab_signaled_state(dh, thread, 1)) {
			EVENTTRACE("%p: event %p already signaled: %d",
				   thread, dh, dh->signal_state);
			/* mark that we are not waiting on this object */
			wb[i].thread = NULL;
		} else {
			assert(timeout == NULL || *timeout != 0);
			assert(thread_wait != NULL);
			wb[i].thread = thread;
			EVENTTRACE("%p: need to wait on event %p", thread, dh);
			InsertTailList(&dh->wait_blocks, &wb[i].list);
		}
	}
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	if (wait_count == 0) {
		assert(thread_wait == NULL);
		EVENTEXIT(return STATUS_SUCCESS);
	}
	assert(thread_wait);

	assert(timeout == NULL || *timeout != 0);
	if (timeout == NULL)
		wait_jiffies = 0;
	else
		wait_jiffies = SYSTEM_TIME_TO_HZ(*timeout) + 1;
	EVENTTRACE("%p: sleeping for %ld on %p",
		   thread, wait_jiffies, thread_wait);

	while (wait_count) {
		if (wait_jiffies) {
			res = wait_event_interruptible_timeout(
				thread_wait->wq_head, (thread_wait->done == 1),
				wait_jiffies);
		} else {
			wait_event_interruptible(
				thread_wait->wq_head,(thread_wait->done == 1));
			/* mark that it didn't timeout */
			res = 1;
		}
		thread_wait->done = 0;
		irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
		if (signal_pending(current))
			res = -ERESTARTSYS;
		EVENTTRACE("%p woke up on %p, res = %d, done: %d", thread,
			   thread_wait, res, thread_wait->done);
#ifdef EVENT_DEBUG
		if (thread_wait->task != current)
			ERROR("%p: argh, task %p should be %p", thread_wait,
			      thread_wait->task, current);
#endif
//		assert(res < 0 && alertable);
		if (res <= 0) {
			/* timed out or interrupted; remove from wait list */
			for (i = 0; i < count; i++) {
				if (!wb[i].thread)
					continue;
				EVENTTRACE("%p: timedout, deq'ing %p (%p)",
					   thread, object[i], wb[i].object);
				RemoveEntryList(&wb[i].list);
			}
			put_thread_event_wait(thread_wait);
			nt_spin_unlock_irql(&dispatcher_lock, irql);
			if (res < 0)
				EVENTEXIT(return STATUS_ALERTED);
			else
				EVENTEXIT(return STATUS_TIMEOUT);
		}
		/* woken up by wakeup_threads */
		for (i = 0; wait_count && i < count; i++) {
			if (!wb[i].thread)
				continue;
			EVENTTRACE("object: %p, %p", object[i], wb[i].object);
			if (!wb[i].object) {
				EVENTTRACE("not woken for %p", object[i]);
				continue;
			}
			DBG_BLOCK(1) {
				if (wb[i].object != object[i]) {
					ERROR("argh, event not signalled? "
					      "%p, %p", wb[i].object,
					      object[i]);
					continue;
				}
			}
			wb[i].object = NULL;
			wb[i].thread = NULL;
			wait_count--;
			if (wait_type == WaitAny) {
				int j;
				/* done; remove from rest of wait list */
				for (j = i; j < count; j++)
					if (wb[j].thread)
						RemoveEntryList(&wb[j].list);
				put_thread_event_wait(thread_wait);
				nt_spin_unlock_irql(&dispatcher_lock, irql);
				EVENTEXIT(return STATUS_WAIT_0 + i);
			}
		}
		if (wait_count == 0) {
			put_thread_event_wait(thread_wait);
			nt_spin_unlock_irql(&dispatcher_lock, irql);
			EVENTEXIT(return STATUS_SUCCESS);
		}
		/* this thread is still waiting for more objects, so
		 * let it wait for remaining time and those objects */
		/* we already set res to 1 if timeout was NULL, so
		 * reinitialize wait_jiffies accordingly */
		if (timeout)
			wait_jiffies = res;
		else
			wait_jiffies = 0;
		nt_spin_unlock_irql(&dispatcher_lock, irql);
	}
	/* this should never reach, but compiler wants return value */
	ERROR("%p: wait_jiffies: %ld", thread, wait_jiffies);
	EVENTEXIT(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(KeWaitForSingleObject)
	(void *object, KWAIT_REASON wait_reason, KPROCESSOR_MODE wait_mode,
	 BOOLEAN alertable, LARGE_INTEGER *timeout)
{
	return KeWaitForMultipleObjects(1, &object, WaitAny, wait_reason,
					wait_mode, alertable, timeout, NULL);
}

wstdcall void WRAP_EXPORT(KeInitializeEvent)
	(struct nt_event *nt_event, enum event_type type, BOOLEAN state)
{
	KIRQL irql;

	EVENTENTER("event = %p, type = %d, state = %d", nt_event, type, state);
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	initialize_dh(&nt_event->dh, type, state);
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	EVENTEXIT(return);
}

wstdcall LONG WRAP_EXPORT(KeSetEvent)
	(struct nt_event *nt_event, KPRIORITY incr, BOOLEAN wait)
{
	LONG old_state;
	KIRQL irql;

	EVENTENTER("event = %p, type = %d, wait = %d",
		   nt_event, nt_event->dh.type, wait);
	if (wait == TRUE)
		WARNING("wait = %d, not yet implemented", wait);
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	old_state = nt_event->dh.signal_state;
	nt_event->dh.signal_state = 1;
	if (old_state == 0)
		wakeup_threads(&nt_event->dh);
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	EVENTEXIT(return old_state);
}

wstdcall void WRAP_EXPORT(KeClearEvent)
	(struct nt_event *nt_event)
{
	EVENTENTER("event = %p", nt_event);
	(void)xchg(&nt_event->dh.signal_state, 0);
	EVENTEXIT(return);
}

wstdcall LONG WRAP_EXPORT(KeResetEvent)
	(struct nt_event *nt_event)
{
	LONG old_state;
	old_state = xchg(&nt_event->dh.signal_state, 0);
	EVENTTRACE("old state: %d", old_state);
	EVENTEXIT(return old_state);
}

wstdcall void WRAP_EXPORT(KeInitializeMutex)
	(struct nt_mutex *mutex, ULONG level)
{
	KIRQL irql;

	EVENTENTER("%p", mutex);
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	initialize_dh(&mutex->dh, MutexObject, 1);
	mutex->dh.size = sizeof(*mutex);
	InitializeListHead(&mutex->list);
	mutex->abandoned = FALSE;
	mutex->apc_disable = 1;
	mutex->owner_thread = NULL;
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	EVENTEXIT(return);
}

wstdcall LONG WRAP_EXPORT(KeReleaseMutex)
	(struct nt_mutex *mutex, BOOLEAN wait)
{
	LONG ret;
	KIRQL irql;
	struct task_struct *thread;

	EVENTENTER("%p, %d, %p", mutex, wait, current);
	if (wait == TRUE)
		WARNING("wait: %d", wait);
	thread = current;
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	EVENTTRACE("%p, %p, %d", thread, mutex->owner_thread,
		   mutex->dh.signal_state);
	if ((mutex->owner_thread == thread) && (mutex->dh.signal_state <= 0)) {
		if ((ret = mutex->dh.signal_state++) == 0) {
			mutex->owner_thread = NULL;
			wakeup_threads(&mutex->dh);
		}
	} else
		ret = STATUS_MUTANT_NOT_OWNED;
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	EVENTTRACE("ret: %08X", ret);
	EVENTEXIT(return ret);
}

wstdcall void WRAP_EXPORT(KeInitializeSemaphore)
	(struct nt_semaphore *semaphore, LONG count, LONG limit)
{
	KIRQL irql;

	EVENTENTER("%p: %d", semaphore, count);
	/* if limit > 1, we need to satisfy as many waits (until count
	 * becomes 0); so we keep decrementing count everytime a wait
	 * is satisified */
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	initialize_dh(&semaphore->dh, SemaphoreObject, count);
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	semaphore->dh.size = sizeof(*semaphore);
	semaphore->limit = limit;
	EVENTEXIT(return);
}

wstdcall LONG WRAP_EXPORT(KeReleaseSemaphore)
	(struct nt_semaphore *semaphore, KPRIORITY incr, LONG adjustment,
	 BOOLEAN wait)
{
	LONG ret;
	KIRQL irql;

	EVENTENTER("%p", semaphore);
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	ret = semaphore->dh.signal_state;
	assert(ret >= 0);
	if (semaphore->dh.signal_state + adjustment <= semaphore->limit)
		semaphore->dh.signal_state += adjustment;
	/* else raise exception */
	if (semaphore->dh.signal_state > 0)
		wakeup_threads(&semaphore->dh);
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	EVENTEXIT(return ret);
}

wstdcall NTSTATUS WRAP_EXPORT(KeDelayExecutionThread)
	(KPROCESSOR_MODE wait_mode, BOOLEAN alertable, LARGE_INTEGER *interval)
{
	int res;
	long timeout;

	if (wait_mode != 0)
		ERROR("invalid wait_mode %d", wait_mode);

	timeout = SYSTEM_TIME_TO_HZ(*interval) + 1;
	EVENTTRACE("thread: %p, interval: %Ld, timeout: %ld",
		    current, *interval, timeout);
	if (timeout <= 0)
		EVENTEXIT(return STATUS_SUCCESS);

	alertable = TRUE;
	if (alertable)
		set_current_state(TASK_INTERRUPTIBLE);
	else
		set_current_state(TASK_UNINTERRUPTIBLE);

	res = schedule_timeout(timeout);
	EVENTTRACE("thread: %p, res: %d", current, res);
	if (res == 0)
		EVENTEXIT(return STATUS_SUCCESS);
	else
		EVENTEXIT(return STATUS_ALERTED);
}

wstdcall KPRIORITY WRAP_EXPORT(KeQueryPriorityThread)
	(struct task_struct *task)
{
	KPRIORITY prio;

	EVENTENTER("task: %p", task);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	prio = 1;
#else
	if (rt_task(task))
		prio = LOW_REALTIME_PRIORITY;
	else
		prio = MAXIMUM_PRIORITY;
#endif
	EVENTEXIT(return prio);
}

wstdcall ULONGLONG WRAP_EXPORT(KeQueryInterruptTime)
	(void)
{
	TRACEEXIT5(return jiffies * TICKSPERSEC / HZ);
}

wstdcall ULONG WRAP_EXPORT(KeQueryTimeIncrement)
	(void)
{
	TRACEEXIT5(return TICKSPERSEC / HZ);
}

wstdcall void WRAP_EXPORT(KeQuerySystemTime)
	(LARGE_INTEGER *time)
{
	*time = ticks_1601();
	return;
}

wstdcall void WRAP_EXPORT(KeQueryTickCount)
	(LARGE_INTEGER *j)
{
	*j = jiffies;
}

wstdcall LARGE_INTEGER WRAP_EXPORT(KeQueryPerformanceCounter)
	(LARGE_INTEGER *counter)
{
	if (counter)
		*counter = HZ;
	return jiffies;
}

wstdcall struct task_struct *WRAP_EXPORT(KeGetCurrentThread)
	(void)
{
	struct task_struct *task = current;

	DBGTRACE5("task: %p", task);
	return task;
}

wstdcall KPRIORITY WRAP_EXPORT(KeSetPriorityThread)
	(struct task_struct *task, KPRIORITY priority)
{
	KPRIORITY old_prio;

	TRACEENTER3("task: %p, priority = %u", task, priority);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	/* FIXME: is there a way to set kernel thread prio on 2.4? */
	old_prio = LOW_PRIORITY;
#else
	if (rt_task(task))
		old_prio = LOW_REALTIME_PRIORITY;
	else
		old_prio = MAXIMUM_PRIORITY;
#if 0
	if (priority == LOW_REALTIME_PRIORITY)
		set_user_nice(task, -20);
	else
		set_user_nice(task, 10);
#endif
#endif
	return old_prio;
}

struct trampoline_context {
	void (*start_routine)(void *) wstdcall;
	void *context;
	struct nt_thread *thread;
};

static int thread_trampoline(void *data)
{
	struct trampoline_context ctx;
	struct nt_thread *thread;

	memcpy(&ctx, data, sizeof(ctx));
	kfree(data);
	thread = ctx.thread;
	thread->task = current;
	thread->pid = thread->task->pid;
#ifdef PF_NOFREEZE
	current->flags |= PF_NOFREEZE;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	strncpy(current->comm, "windisdrvr", sizeof(current->comm));
	current->comm[sizeof(current->comm) - 1] = 0;
#endif
	DBGTRACE2("thread: %p, task: %p (%d)", thread, thread->task,
		  thread->pid);
	ctx.start_routine(ctx.context);

	return 0;
}

static struct nt_thread *create_nt_thread(struct task_struct *task)
{
	struct nt_thread *thread;
	KIRQL irql;

	thread = allocate_object(sizeof(*thread), OBJECT_TYPE_NT_THREAD, NULL);
	if (!thread) {
		ERROR("couldn't allocate thread object");
		return NULL;
	}
	thread->task = task;
	if (task)
		thread->pid = task->pid;
	else
		thread->pid = 0;
	nt_spin_lock_init(&thread->lock);
	InitializeListHead(&thread->irps);
	irql = nt_spin_lock_irql(&dispatcher_lock, DISPATCH_LEVEL);
	initialize_dh(&thread->dh, ThreadObject, 0);
	thread->dh.size = sizeof(*thread);
	nt_spin_unlock_irql(&dispatcher_lock, irql);
	DBGTRACE2("thread: %p, task: %p, pid: %d",
		  thread, thread->task, thread->pid);
	return thread;
}

static void remove_nt_thread(struct nt_thread *thread)
{
	struct nt_list *ent;
	KIRQL irql;

	if (!thread) {
		ERROR("invalid thread");
		return;
	}
	DBGTRACE1("terminating thread: %p, task: %p, pid: %d",
		  thread, thread->task, thread->task->pid);
	/* TODO: make sure waitqueue is empty and destroy it */
	while (1) {
		struct irp *irp;
		irql = nt_spin_lock_irql(&thread->lock, DISPATCH_LEVEL);
		ent = RemoveHeadList(&thread->irps);
		nt_spin_unlock_irql(&thread->lock, irql);
		if (!ent)
			break;
		irp = container_of(ent, struct irp, threads);
		IoCancelIrp(irp);
	}
	ObDereferenceObject(thread);
}

struct nt_thread *get_current_nt_thread(void)
{
	struct task_struct *task = current;
	struct nt_thread *ret;
	struct common_object_header *header;
	KIRQL irql;

	DBGTRACE5("task: %p", task);
	ret = NULL;
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(header, &object_list, list) {
		struct nt_thread *thread;
		DBGTRACE5("header: %p, type: %d", header, header->type);
		if (header->type != OBJECT_TYPE_NT_THREAD)
			break;
		thread = HEADER_TO_OBJECT(header);
		DBGTRACE5("thread: %p, task: %p", thread, thread->task);
		if (thread->task == task) {
			ret = thread;
			break;
		}
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	if (ret == NULL)
		DBGTRACE3("couldn't find thread for task %p, %d",
			  task, current->pid);
	DBGTRACE5("current thread = %p", ret);
	return ret;
}

wstdcall NTSTATUS WRAP_EXPORT(PsCreateSystemThread)
	(void **phandle, ULONG access, void *obj_attr, void *process,
	 void *client_id, void (*start_routine)(void *) wstdcall, void *context)
{
	struct trampoline_context *ctx;
	struct nt_thread *thread;
	struct task_struct *task;
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
	ctx->start_routine = start_routine;
	ctx->context = context;
	thread = create_nt_thread(NULL);
	if (!thread) {
		kfree(ctx);
		TRACEEXIT2(return STATUS_RESOURCES);
	}
	ctx->thread = thread;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
	pid = kernel_thread(thread_trampoline, ctx,
			    CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	DBGTRACE2("pid = %d", pid);
	if (pid < 0) {
		kfree(ctx);
		free_object(thread);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	task = NULL;
	DBGTRACE2("created task: %p (%d)", task, pid);
#else
	task = KTHREAD_RUN(thread_trampoline, ctx, "windisdrvr");
	if (IS_ERR(task)) {
		kfree(ctx);
		free_object(thread);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	DBGTRACE2("created task: %p (%d)", task, task->pid);
#endif
	*phandle = OBJECT_TO_HEADER(thread);
	DBGTRACE2("created thread: %p, %p", thread, *phandle);
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(PsTerminateSystemThread)
	(NTSTATUS status)
{
	struct nt_thread *thread;

	DBGTRACE2("%p, %08X", current, status);
	thread = get_current_nt_thread();
	if (thread) {
		DBGTRACE2("setting event for thread: %p", thread);
		KeSetEvent((struct nt_event *)&thread->dh, 0, FALSE);
		DBGTRACE2("set event for thread: %p", thread);
		remove_nt_thread(thread);
		complete_and_exit(NULL, status);
		ERROR("oops: %p, %d", thread->task, thread->pid);
	} else
		ERROR("couldn't find thread for task: %p", current);
	return STATUS_FAILURE;
}

wstdcall BOOLEAN WRAP_EXPORT(KeRemoveEntryDeviceQueue)
	(struct kdevice_queue *dev_queue, struct kdevice_queue_entry *entry)
{
	struct kdevice_queue_entry *e;
	KIRQL irql;

	irql = nt_spin_lock_irql(&dev_queue->lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(e, &dev_queue->list, list) {
		if (e == entry) {
			RemoveEntryList(&e->list);
			nt_spin_unlock_irql(&dev_queue->lock, irql);
			return TRUE;
		}
	}
	nt_spin_unlock_irql(&dev_queue->lock, irql);
	return FALSE;
}

wstdcall BOOLEAN WRAP_EXPORT(KeSynchronizeExecution)
	(struct kinterrupt *interrupt, PKSYNCHRONIZE_ROUTINE synch_routine,
	 void *synch_context)
{
	NT_SPIN_LOCK *spinlock;
	BOOLEAN ret;
	unsigned long flags;

	if (interrupt->actual_lock)
		spinlock = interrupt->actual_lock;
	else
		spinlock = &interrupt->lock;
	nt_spin_lock_irqsave(spinlock, flags);
	ret = synch_routine(synch_context);
	nt_spin_unlock_irqrestore(spinlock, flags);
	return ret;
}

wstdcall void *WRAP_EXPORT(MmAllocateContiguousMemorySpecifyCache)
	(SIZE_T size, PHYSICAL_ADDRESS lowest, PHYSICAL_ADDRESS highest,
	 PHYSICAL_ADDRESS boundary, enum memory_caching_type cache_type)
{
	void *addr;
	DBGTRACE2("%lu, %Lu, %Lu, %Lu, %d", size, lowest, highest, boundary,
		  cache_type);
	addr = ExAllocatePoolWithTag(NonPagedPool, size, 0);
	DBGTRACE2("%p", addr);
	return addr;
}

wstdcall void WRAP_EXPORT(MmFreeContiguousMemorySpecifyCache)
	(void *base, SIZE_T size, enum memory_caching_type cache_type)
{
	DBGTRACE2("%p", base);
	ExFreePool(base);
}

wstdcall PHYSICAL_ADDRESS WRAP_EXPORT(MmGetPhysicalAddress)
	(void *base)
{
	DBGTRACE2("%p", base);
	return virt_to_phys(base);
}

/* Atheros card with pciid 168C:0014 calls this function with 0xf0000
 * and 0xf6ef0 address, and then check for things that seem to be
 * related to ACPI: "_SM_" and "_DMI_". This may be the hack they do
 * to check if this card is installed in IBM thinkpads; we can
 * probably get this device to work if we create a buffer with the
 * strings as required by the driver and return virtual address for
 * that address instead */
wstdcall void *WRAP_EXPORT(MmMapIoSpace)
	(PHYSICAL_ADDRESS phys_addr, SIZE_T size,
	 enum memory_caching_type cache)
{
	void *virt;
	TRACEENTER1("cache type: %d", cache);
	if (cache == MmCached)
		virt = ioremap(phys_addr, size);
	else
		virt = ioremap_nocache(phys_addr, size);
	DBGTRACE1("%Lx, %lu, %p", phys_addr, size, virt);
	return virt;
}

wstdcall void WRAP_EXPORT(MmUnmapIoSpace)
	(void *addr, SIZE_T size)
{
	TRACEENTER1("%p, %lu", addr, size);
	iounmap(addr);
	return;
}

wstdcall ULONG WRAP_EXPORT(MmSizeOfMdl)
	(void *base, ULONG length)
{
	return (sizeof(struct mdl) +
		(sizeof(PFN_NUMBER) * SPAN_PAGES(base, length)));
}

struct mdl *allocate_init_mdl(void *virt, ULONG length)
{
	struct wrap_mdl *wrap_mdl;
	struct mdl *mdl = NULL;
	int mdl_size = MmSizeOfMdl(virt, length);
	KIRQL irql;

	if (mdl_size <= CACHE_MDL_SIZE) {
		unsigned int alloc_flags;

		if (current_irql() < DISPATCH_LEVEL)
			alloc_flags = GFP_KERNEL;
		else
			alloc_flags = GFP_ATOMIC;
		wrap_mdl = kmem_cache_alloc(mdl_cache, alloc_flags);
		if (!wrap_mdl)
			return NULL;
		irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		InsertHeadList(&wrap_mdl_list, &wrap_mdl->list);
		nt_spin_unlock_irql(&ntoskernel_lock, irql);
		mdl = (struct mdl *)wrap_mdl->mdl;
		DBGTRACE3("allocated mdl from cache: %p(%p), %p(%d)",
			  wrap_mdl, mdl, virt, length);
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
		mdl = (struct mdl *)wrap_mdl->mdl;
		DBGTRACE3("allocated mdl from memory: %p(%p), %p(%d)",
			  wrap_mdl, mdl, virt, length);
		irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		InsertHeadList(&wrap_mdl_list, &wrap_mdl->list);
		nt_spin_unlock_irql(&ntoskernel_lock, irql);
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
		irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
		RemoveEntryList(&wrap_mdl->list);
		nt_spin_unlock_irql(&ntoskernel_lock, irql);

		if (mdl->flags & MDL_CACHE_ALLOCATED) {
			DBGTRACE3("freeing mdl cache: %p, %p, %p",
				  wrap_mdl, mdl, mdl->mappedsystemva);
			kmem_cache_free(mdl_cache, wrap_mdl);
		} else {
			DBGTRACE3("freeing mdl: %p, %p, %p",
				  wrap_mdl, mdl, mdl->mappedsystemva);
			kfree(wrap_mdl);
		}
	}
	return;
}

wstdcall void WRAP_EXPORT(IoBuildPartialMdl)
	(struct mdl *source, struct mdl *target, void *virt, ULONG length)
{
	MmInitializeMdl(target, virt, length);
	target->flags |= MDL_PARTIAL;
}

/* FIXME: We don't update MDL to physical page mapping, since in Linux
 * the pages are in memory anyway; if a driver treats an MDL as
 * opaque, we should be safe; otherwise, the driver may break */
wstdcall void WRAP_EXPORT(MmBuildMdlForNonPagedPool)
	(struct mdl *mdl)
{
	PFN_NUMBER *mdl_pages;
	int i, n;
	TRACEENTER4("%p", mdl);
	/* already mapped */
//	mdl->mappedsystemva = MmGetMdlVirtualAddress(mdl);
	mdl->flags |= MDL_SOURCE_IS_NONPAGED_POOL;
	DBGTRACE4("%p, %p, %p, %d, %d", mdl, mdl->mappedsystemva, mdl->startva,
		  mdl->byteoffset, mdl->bytecount);
	n = SPAN_PAGES(MmGetSystemAddressForMdl(mdl), MmGetMdlByteCount(mdl));
	if (n > CACHE_MDL_PAGES)
		WARNING("%p, %d, %d", MmGetSystemAddressForMdl(mdl),
			MmGetMdlByteCount(mdl), n);
	mdl_pages = MmGetMdlPfnArray(mdl);
	for (i = 0; i < n; i++)
		mdl_pages[i] = (ULONG_PTR)mdl->startva + (i * PAGE_SIZE);
	return;
}

wstdcall void *WRAP_EXPORT(MmMapLockedPages)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode)
{
	/* already mapped */
//	mdl->mappedsystemva = MmGetMdlVirtualAddress(mdl);
	mdl->flags |= MDL_MAPPED_TO_SYSTEM_VA;
	/* what is the need for MDL_PARTIAL_HAS_BEEN_MAPPED? */
	if (mdl->flags & MDL_PARTIAL)
		mdl->flags |= MDL_PARTIAL_HAS_BEEN_MAPPED;
	return mdl->mappedsystemva;
}

wstdcall void *WRAP_EXPORT(MmMapLockedPagesSpecifyCache)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode,
	 enum memory_caching_type cache_type, void *base_address,
	 ULONG bug_check, enum mm_page_priority priority)
{
	return MmMapLockedPages(mdl, access_mode);
}

wstdcall void WRAP_EXPORT(MmUnmapLockedPages)
	(void *base, struct mdl *mdl)
{
	mdl->flags &= ~MDL_MAPPED_TO_SYSTEM_VA;
	return;
}

wstdcall void WRAP_EXPORT(MmProbeAndLockPages)
	(struct mdl *mdl, KPROCESSOR_MODE access_mode,
	 enum lock_operation operation)
{
	/* already locked */
	mdl->flags |= MDL_PAGES_LOCKED;
	return;
}

wstdcall void WRAP_EXPORT(MmUnlockPages)
	(struct mdl *mdl)
{
	mdl->flags &= ~MDL_PAGES_LOCKED;
	return;
}

wstdcall BOOLEAN WRAP_EXPORT(MmIsAddressValid)
	(void *virt_addr)
{
	if (virt_addr_valid(virt_addr))
		return TRUE;
	else
		return FALSE;
}

wstdcall void *WRAP_EXPORT(MmLockPagableDataSection)
	(void *address)
{
	return address;
}

wstdcall void WRAP_EXPORT(MmUnlockPagableImageSection)
	(void *handle)
{
	return;
}

wstdcall NTSTATUS WRAP_EXPORT(ObReferenceObjectByHandle)
	(void *handle, ACCESS_MASK desired_access, void *obj_type,
	 KPROCESSOR_MODE access_mode, void **object, void *handle_info)
{
	struct common_object_header *hdr;
	KIRQL irql;

	DBGTRACE2("%p", handle);
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = HANDLE_TO_HEADER(handle);
	hdr->ref_count++;
	*object = HEADER_TO_OBJECT(hdr);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE2("%p, %p, %d, %p", hdr, object, hdr->ref_count, *object);
	return STATUS_SUCCESS;
}

/* DDK doesn't say if return value should be before incrementing or
 * after incrementing reference count, but according to #reactos
 * devels, it should be return value after incrementing */
wfastcall LONG WRAP_EXPORT(ObfReferenceObject)
	(void *object)
{
	struct common_object_header *hdr;
	LONG ret;
	KIRQL irql;

	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = OBJECT_TO_HEADER(object);
	ret = ++hdr->ref_count;
	DBGTRACE2("%p, %d, %p", hdr, hdr->ref_count, object);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	return ret;
}

wfastcall void WRAP_EXPORT(ObfDereferenceObject)
	(void *object)
{
	struct common_object_header *hdr;
	int ref_count;
	KIRQL irql;

	TRACEENTER2("object: %p", object);
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	hdr = OBJECT_TO_HEADER(object);
	DBGTRACE2("hdr: %p", hdr);
	hdr->ref_count--;
	ref_count = hdr->ref_count;
	DBGTRACE2("object: %p, %d", object, ref_count);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	if (ref_count < 0)
		ERROR("invalid object: %p (%d)", object, ref_count);
	if (ref_count <= 0) {
		free_object(object);
	}
}

wstdcall NTSTATUS WRAP_EXPORT(ZwCreateFile)
	(void **handle, ULONG access_mask, struct object_attr *obj_attr,
	 struct io_status_block *iosb, LARGE_INTEGER *size,
	 ULONG file_attr, ULONG share_access, ULONG create_disposition,
	 ULONG create_options, void *ea_buffer, ULONG ea_length)
{
	struct common_object_header *header;
	struct object_attr *oa;
	struct ansi_string ansi;
	struct wrap_bin_file *bin_file;
	char *file_basename;
	KIRQL irql;

	TRACEENTER2("%p", *handle);
	if (RtlUnicodeStringToAnsiString(&ansi, obj_attr->name, TRUE) !=
	    STATUS_SUCCESS)
		TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
	DBGTRACE2("Filename: %s", ansi.buf);

	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(header, &object_list, list) {
		if (header->type != OBJECT_TYPE_FILE)
			continue;
		oa = HEADER_TO_OBJECT(header);
		if (!RtlCompareUnicodeString(oa->name, obj_attr->name,
					     FALSE)) {
			bin_file = oa->file;
			*handle = header;
			iosb->status = FILE_OPENED;
			iosb->info = bin_file->size;
			nt_spin_unlock_irql(&ntoskernel_lock, irql);
			TRACEEXIT2(return STATUS_SUCCESS);
		}
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);

	oa = allocate_object(sizeof(struct object_attr), OBJECT_TYPE_FILE,
			     ansi.buf);
	if (!oa) {
		iosb->status = FILE_DOES_NOT_EXIST;
		iosb->info = 0;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	*handle = OBJECT_TO_HEADER(oa);
	DBGTRACE2("handle: %p", *handle);
	file_basename = strrchr(ansi.buf, '\\');
	if (file_basename)
		file_basename++;
	else
		file_basename = ansi.buf;
	DBGTRACE2("file_basename: '%s'", file_basename);
	bin_file = get_bin_file(file_basename);
	if (bin_file) {
		oa->file = bin_file;
		iosb->status = FILE_OPENED;
		iosb->info = bin_file->size;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return STATUS_SUCCESS);
	} else {
		iosb->status = FILE_DOES_NOT_EXIST;
		iosb->info = 0;
		RtlFreeAnsiString(&ansi);
		TRACEEXIT2(return STATUS_FAILURE);
	}
}

wstdcall NTSTATUS WRAP_EXPORT(ZwReadFile)
	(void *handle, struct nt_event *event, void *apc_routine,
	 void *apc_context, struct io_status_block *iosb, void *buffer,
	 ULONG length, LARGE_INTEGER *byte_offset, ULONG *key)
{
	struct object_attr *oa;
	struct common_object_header *coh;
	ULONG count;
	size_t offset;
	struct wrap_bin_file *file;

	DBGTRACE2("%p", handle);
	coh = handle;
	if (coh->type != OBJECT_TYPE_FILE) {
		ERROR("handle %p is not for a file: %d", handle, coh->type);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	oa = HANDLE_TO_OBJECT(coh);
	file = oa->file;
	DBGTRACE2("file: %s (%d)", file->name, file->size);
	if (byte_offset)
		offset = *byte_offset;
	else
		offset = 0;
	count = min((size_t)length, file->size - offset);
	DBGTRACE2("count: %u, offset: %zu, length: %u", count, offset, length);
	memcpy(buffer, ((void *)file->data) + offset, count);
	iosb->status = STATUS_SUCCESS;
	iosb->info = count;
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(ZwClose)
	(void *handle)
{
	struct object_attr *oa;
	struct common_object_header *coh;
	struct wrap_bin_file *bin_file;

	DBGTRACE2("%p", handle);
	if (handle == NULL) {
		DBGTRACE1("");
		TRACEEXIT2(return STATUS_SUCCESS);
	}
	coh = handle;
	oa = HANDLE_TO_OBJECT(handle);
	if (coh->type == OBJECT_TYPE_FILE) {
		bin_file = oa->file;
		free_bin_file(bin_file);
		ObDereferenceObject(oa);
	} else if (coh->type == OBJECT_TYPE_NT_THREAD) {
		DBGTRACE1("thread: %p", handle);
	}
	else
		WARNING("closing handle %p not implemented", handle);
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(ZwQueryInformationFile)
	(void *handle, struct io_status_block *iosb, void *info,
	 ULONG length, enum file_info_class class)
{
	struct object_attr *oa;
	struct file_name_info *fni;
	struct file_std_info *fsi;
	struct wrap_bin_file *file;
	struct common_object_header *coh;

	TRACEENTER2("%p", handle);
	coh = handle;
	if (coh->type != OBJECT_TYPE_FILE) {
		ERROR("handle %p is not for a file: %d", handle, coh->type);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	oa = HANDLE_TO_OBJECT(handle);
	DBGTRACE2("attr: %p", oa);
	switch (class) {
	case FileNameInformation:
		fni = info;
		fni->length = oa->name->max_length;
		memcpy(fni->name, oa->name->buf, oa->name->max_length);
		break;
	case FileStandardInformation:
		fsi = info;
		file = oa->file;
		fsi->alloc_size = file->size;
		fsi->eof = file->size;
		fsi->num_links = 1;
		fsi->delete_pending = FALSE;
		fsi->dir = FALSE;
		break;
	default:
		WARNING("type %d not implemented yet", class);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(ZwCreateKey)
	(void **handle, ACCESS_MASK desired_access, struct object_attr *attr,
	 ULONG title_index, struct unicode_string *class,
	 ULONG create_options, ULONG *disposition)
{
	struct ansi_string ansi;
	if (RtlUnicodeStringToAnsiString(&ansi, attr->name, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE1("key: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	*handle = NULL;
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(ZwOpenKey)
	(void **handle, ACCESS_MASK desired_access, struct object_attr *attr)
{
	struct ansi_string ansi;
	if (RtlUnicodeStringToAnsiString(&ansi, attr->name, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE1("key: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	*handle = NULL;
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(ZwSetValueKey)
	(void *handle, struct unicode_string *name, ULONG title_index,
	 ULONG type, void *data, ULONG data_size)
{
	struct ansi_string ansi;
	if (RtlUnicodeStringToAnsiString(&ansi, name, TRUE) ==
	    STATUS_SUCCESS) {
		DBGTRACE1("key: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(ZwQueryValueKey)
	(void *handle, struct unicode_string *name,
	 enum key_value_information_class class, void *info,
	 ULONG length, ULONG *res_length)
{
	struct ansi_string ansi;
	if (RtlUnicodeStringToAnsiString(&ansi, name, TRUE) == STATUS_SUCCESS) {
		DBGTRACE1("key: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	UNIMPL();
	return STATUS_INVALID_PARAMETER;
}

wstdcall NTSTATUS WRAP_EXPORT(WmiSystemControl)
	(struct wmilib_context *info, struct device_object *dev_obj,
	 struct irp *irp, void *irp_disposition)
{
	UNIMPL();
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(WmiCompleteRequest)
	(struct device_object *dev_obj, struct irp *irp, NTSTATUS status,
	 ULONG buffer_used, CCHAR priority_boost)
{
	UNIMPL();
	return STATUS_SUCCESS;
}

noregparm NTSTATUS WRAP_EXPORT(WmiTraceMessage)
	(void *tracehandle, ULONG message_flags,
	 void *message_guid, USHORT message_no, ...)
{
	UNIMPL();
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(WmiQueryTraceInformation)
	(enum trace_information_class trace_info_class, void *trace_info,
	 ULONG *req_length, void *buf)
{
	UNIMPL();
	TRACEEXIT2(return STATUS_SUCCESS);
}

/* this function can't be wstdcall as it takes variable number of args */
noregparm ULONG WRAP_EXPORT(DbgPrint)
	(char *format, ...)
{
#ifdef DEBUG
	va_list args;
	static char buf[100];

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	printk(KERN_DEBUG "%s (%s): %s", DRIVER_NAME, __FUNCTION__, buf);
	va_end(args);
#endif
	return STATUS_SUCCESS;
}

wstdcall void WRAP_EXPORT(KeBugCheckEx)
	(ULONG code, ULONG_PTR param1, ULONG_PTR param2,
	 ULONG_PTR param3, ULONG_PTR param4)
{
	UNIMPL();
	return;
}

wstdcall void WRAP_EXPORT(ExSystemTimeToLocalTime)
	(LARGE_INTEGER *system_time, LARGE_INTEGER *local_time)
{
	*local_time = *system_time;
}

wstdcall ULONG WRAP_EXPORT(ExSetTimerResolution)
	(ULONG time, BOOLEAN set)
{
	/* yet another "innovation"! */
	return time;
}

wstdcall void WRAP_EXPORT(DbgBreakPoint)(void){UNIMPL();}
wstdcall void WRAP_EXPORT(_except_handler3)(void){UNIMPL();}
wstdcall void WRAP_EXPORT(__C_specific_handler)(void){UNIMPL();}
void WRAP_EXPORT(_purecall)(void) { UNIMPL(); }

#include "ntoskernel_exports.h"
