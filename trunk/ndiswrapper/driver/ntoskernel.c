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

#include "ntoskernel.h"
#include "wrapper.h"
#include "ndis.h"
#include "usb.h"

unsigned long long KeTickCount;
STDCALL static void
WRITE_REGISTER_ULONG(unsigned int reg, unsigned int val)
{
	writel(val, reg);
}

STDCALL static void
WRITE_REGISTER_USHORT(unsigned int reg, unsigned short val)
{
	writew(val, reg);
}

STDCALL static void
WRITE_REGISTER_UCHAR(unsigned int reg, unsigned char val)
{
	writeb(val, reg);
}

STDCALL static void
KeInitializeTimer(struct ktimer *ktimer)
{
	TRACEENTER4("%p", ktimer);
	wrapper_init_timer(ktimer, NULL);
	ktimer->dispatch_header.signal_state = 0;
}

STDCALL static void
KeInitializeDpc(struct kdpc *kdpc, void *func, void *ctx)
{
	TRACEENTER4("%p, %p, %p", kdpc, func, ctx);
	init_dpc(kdpc, func, ctx);
}

STDCALL static int
KeSetTimerEx(struct ktimer *ktimer, __s64 due_time, __u32 period,
	     struct kdpc *kdpc)
{
	unsigned long expires;
	unsigned long repeat;

	TRACEENTER4("%p, %ld, %u, %p", ktimer, (long)due_time, period, kdpc);

	if (ktimer == NULL)
		return 0;
	if (due_time < 0)
		expires = jiffies + HZ * (-due_time / 10000000);
	else
		expires = HZ * (due_time / 10000000);
	repeat = HZ * (period / 1000);
	if (kdpc)
		wrapper_set_timer_dpc(ktimer->wrapper_timer, kdpc);
	return wrapper_set_timer(ktimer->wrapper_timer, expires, repeat);
}

STDCALL static int
KeSetTimer(struct ktimer *ktimer, __s64 due_time, struct kdpc *kdpc)
{
	TRACEENTER4("%p, %ld, %u, %p", ktimer, (long)due_time, kdpc);
	return KeSetTimerEx(ktimer, due_time, 0, kdpc);
}

STDCALL static int
KeCancelTimer(struct ktimer *ktimer)
{
	char canceled;

	TRACEENTER4("%p", ktimer);
	wrapper_cancel_timer(ktimer->wrapper_timer, &canceled);
	return canceled;
}

STDCALL KIRQL
KeGetCurrentIrql(void)
{
	if (in_atomic() || irqs_disabled())
		return DISPATCH_LEVEL;
	else
		return PASSIVE_LEVEL;
}

STDCALL void
KeInitializeSpinLock(KSPIN_LOCK *lock)
{
	struct wrap_spinlock *spin_lock;

	if (!lock)
	{
		ERROR("%s", "invalid lock");
		return;
	}

	spin_lock = wrap_kmalloc(sizeof(struct wrap_spinlock), GFP_ATOMIC);
	if (!spin_lock)
		ERROR("%s", "Couldn't allocate space for spinlock");
	else
	{
		DBGTRACE4("allocated spinlock %p", spin_lock);
		wrap_spin_lock_init(spin_lock);
		*lock = (KSPIN_LOCK)spin_lock;
	}
}

STDCALL static void
KeAcquireSpinLock(KSPIN_LOCK *lock, KIRQL *oldirql)
{
	TRACEENTER4("lock = %p, *lock = %p", lock, (void *)*lock);

	if (!lock)
	{
		ERROR("%s", "invalid lock");
		return;
	}

	if (!*lock)
	{
		printk(KERN_WARNING "Buggy Windows driver trying to use "
		       "uninitialized lock. Trying to recover...");
		KeInitializeSpinLock(lock);
		if (*lock)
			printk(KERN_WARNING "ok\n");
		else
		{
			printk(KERN_WARNING "failed\n");
			BUG();
		}
	}
	wrap_spin_lock((struct wrap_spinlock *)*lock);
	TRACEEXIT4(return);
}

STDCALL static void
KeReleaseSpinLock(KSPIN_LOCK *lock, KIRQL newirql)
{
	TRACEENTER4("lock = %p, *lock = %p", lock, (void *)*lock);

	if (!lock || !*lock)
	{
		ERROR("invalid spin lock %p", lock);
		return;
	}

	wrap_spin_unlock((struct wrap_spinlock *)*lock);
}

_FASTCALL static struct slist_entry *
ExInterlockedPushEntrySList(int dummy, struct slist_entry *entry,
			    union slist_head *head, KSPIN_LOCK *lock)
{
	struct slist_entry *oldhead;
	KIRQL irql;

	TRACEENTER3("head = %p, entry = %p", head, entry);

//	__asm__ __volatile__ ("" : "=c" (head), "=d" (entry));

	KeAcquireSpinLock(lock, &irql);
	oldhead = head->list.next;
	entry->next = head->list.next;
	head->list.next = entry;
	KeReleaseSpinLock(lock, irql);
	DBGTRACE3("head = %p, oldhead = %p", head, oldhead);
	return(oldhead);
}

_FASTCALL static struct slist_entry *
ExInterlockedPopEntrySList(int dummy, KSPIN_LOCK *lock, union slist_head *head)
{
	struct slist_entry *first;
	KIRQL irql;

	TRACEENTER3("head = %p", head);
//	__asm__ __volatile__ ("" : "=c" (head));
	KeAcquireSpinLock(lock, &irql);
	first = NULL;
	if (head)
	{
		first = head->list.next;
		if (first)
		{
			head->list.next = first->next;
		}
	}
	KeReleaseSpinLock(lock, irql);
	DBGTRACE3("returning %p", first);
	return first;
}

STDCALL static void *
ExAllocatePoolWithTag(enum pool_type pool_type, size_t size, unsigned long tag)
{
	TRACEENTER1("pool_type: %d, size: %d, tag: %lu", pool_type, size, tag);

	/* FIXME: should this function allocate using kmem_cache/mem_pool
	   instead? */
	return kmalloc(size, GFP_ATOMIC);
}

STDCALL static void
ExFreePool(void *p)
{
	TRACEENTER2("%p", p);
	kfree(p);
	TRACEEXIT2(return);
}

STDCALL static void
ExInitializeNPagedLookasideList(struct npaged_lookaside_list *lookaside,
				 LOOKASIDE_ALLOC_FUNC *alloc_func,
				 LOOKASIDE_FREE_FUNC *free_func,
				 unsigned long flags, unsigned long size,
				 unsigned long tag, unsigned short depth)
{
	TRACEENTER3("lookaside: %p, size: %lu, flags: %lu,"
		    " head: %p, size of lookaside: %u\n",
		    lookaside, size, flags, lookaside->head.list.next,
		    sizeof(struct npaged_lookaside_list));

	memset(lookaside, 0, sizeof(*lookaside));

	lookaside->size = size;
	lookaside->tag = tag;
	lookaside->depth = 4;
	lookaside->maxdepth = 256;

	if (alloc_func)
		lookaside->alloc_func = alloc_func;
	else
		lookaside->alloc_func = ExAllocatePoolWithTag;
	if (free_func)
		lookaside->free_func = free_func;
	else
		lookaside->free_func = ExFreePool;

	KeInitializeSpinLock(&lookaside->obsolete);
	TRACEEXIT3(return);
}

STDCALL static void
ExDeleteNPagedLookasideList(struct npaged_lookaside_list *lookaside)
{
	struct slist_entry *entry, *p;

	TRACEENTER3("ookaside = %p", lookaside);
	entry = lookaside->head.list.next;
	while (entry)
	{
		p = entry;
		entry = entry->next;
		lookaside->free_func(p);
	}
	TRACEEXIT4(return);
}


_FASTCALL static void
ExInterlockedAddLargeStatistic(int dummy, u32 n, u64 *plint)
{
	unsigned long flags;
	static spinlock_t lock = SPIN_LOCK_UNLOCKED;
	/* we should have one lock per driver, but since it is used only
	 * here, no harm in having a global lock, for simplicity sake
	 */

	TRACEENTER3("Stat %p = %llu, n = %u", plint, *plint, n);
	spin_lock_irqsave(&lock, flags);
	*plint += n;
	spin_unlock_irqrestore(&lock, flags);
}

STDCALL static void *
MmMapIoSpace(__s64 phys_addr, unsigned long size, int cache)
{
	void *virt;
	if (cache)
		virt = ioremap(phys_addr, size);
	else
		virt = ioremap_nocache(phys_addr, size);
	DBGTRACE3("%Lx, %lu, %d: %p", phys_addr, size, cache, virt);
	return virt;
}

STDCALL static void
MmUnmapIoSpace(void *addr, unsigned long size)
{
	TRACEENTER3("%p, %lu", addr, size);
	iounmap(addr);
	return;
}

STDCALL static int
IoIsWdmVersionAvailable(unsigned char major, unsigned char minor)
{
	TRACEENTER3("%d, %d", major, minor);
	if (major == 1 &&
	    (minor == 0x30 || // Windows 2003
	     minor == 0x20 || // Windows XP
	     minor == 0x10)) // Windows 2000
		return 1;
	return 0;
}

STDCALL static void
KeInitializeEvent(struct kevent *event, int event_type, int state)
{
	TRACEENTER("event = %p, event_type = %d, state = %d",
		event, event_type, state);
	event->header.type         = event_type;
	event->header.signal_state = state;
}

STDCALL static long
KeSetEvent(struct kevent *event, int incr, int wait)
{
	TRACEENTER("event = %p, incr = %d, wait = %d", event, incr, wait);
	NdisSetEvent((struct ndis_event *)event);
	return STATUS_SUCCESS;
}

STDCALL static void
KeClearEvent(struct kevent *event)
{
	TRACEENTER("event = %p", event);
	event->header.signal_state = 0;
}

STDCALL static long
KeResetEvent(struct kevent *event)
{
	long old_state = event->header.signal_state;

	TRACEENTER("event = %p", event);
	event->header.signal_state = 0;
	return old_state;
}

STDCALL static unsigned int
KeWaitForSingleObject(void *object, unsigned int reason,
		      unsigned int waitmode, unsigned short alertable,
		      u64 *timeout)
{
	unsigned int ndis_timeout = 0;

	/* Note: for now, object can only point to an event */
	TRACEENTER3("object = %p, reason = %u, waitmode = %u, alertable = %u,"
		" timeout = %p", object, reason, waitmode, alertable,
		timeout);

	if (timeout) {
		/* absolute timeouts are not yet supported */
		if (*timeout > 0) {
			UNIMPL();
			ndis_timeout = 1000;
		} else if (*timeout == 0) {
			if (((struct kevent *)object)->header.signal_state)
				TRACEEXIT3(return STATUS_SUCCESS);
			else
				TRACEEXIT3(return STATUS_TIMEOUT);
		} else
			ndis_timeout = *timeout / 10000;
	}

	if (!NdisWaitEvent(object, ndis_timeout))
		TRACEEXIT3(return STATUS_TIMEOUT);

	if (((struct kevent *)object)->header.type == SYNCHRONIZATION_EVENT)
		((struct kevent *)object)->header.signal_state = 0;
	TRACEEXIT3(return STATUS_SUCCESS);
}

STDCALL static void
IoBuildSynchronousFsdRequest(void)
{
	UNIMPL();
}

/* this function can't be STDCALL as it takes variable number of args */
NOREGPARM unsigned long
DbgPrint(char *format, ...)
{
	int res = 0;

#ifdef DEBUG
	va_list args;
	static char buf[1024];

	va_start(args, format);
	res = vsnprintf(buf, sizeof(buf), format, args);
	printk("DbgPrint: ");
	printk(buf);
	va_end(args);
#endif
	return res;

}

STDCALL static void DbgBreakPoint(void)
{
	UNIMPL();
}

STDCALL static struct irp *
IoAllocateIrp(char stack_size, unsigned char charge_quota)
{
	struct irp *irp;
	int size;

	TRACEENTER3("stack_size = %d, charge_quota = %d",
		stack_size, charge_quota);

	size = sizeof(struct irp) +
		stack_size * sizeof(struct io_stack_location);
	/* FIXME: we should better check what GFP_ is required */
	irp = kmalloc(size, GFP_ATOMIC);
	if (irp) {
		DBGTRACE3("allocated irp %p", irp);
		memset(irp, 0, size);

		irp->size       = size;
		irp->stack_size = stack_size;
		irp->stack_pos  = stack_size;
		irp->current_stack_location =
			((struct io_stack_location *)(irp+1)) + stack_size;
	}

	TRACEEXIT3(return irp);
}

STDCALL static struct irp *
IoBuildDeviceIoControlRequest(unsigned long ioctl,
                              struct device_object *dev_obj,
                              void *input_buf, unsigned long input_buf_len,
                              void *output_buf, unsigned long output_buf_len,
                              unsigned char internal_ioctl,
                              struct kevent *event,
                              struct io_status_block *io_status)
{
	struct irp *irp;
	struct io_stack_location *stack;

	TRACEENTER3("ioctl = %lx, dev_obj = %p, input_buf = %p, "
		"input_buf_len = %lu, output_buf = %p, output_buf_len = %lu, "
		"internal_ioctl = %d, event = %p, io_status = %p",
		ioctl, dev_obj, input_buf, input_buf_len, output_buf,
		output_buf_len, internal_ioctl, event, io_status);

	irp = kmalloc(sizeof(struct irp) + sizeof(struct io_stack_location),
		GFP_KERNEL); /* we are running at IRQL = PASSIVE_LEVEL */
	if (irp) {
		DBGTRACE3("allocated irp %p", irp);
		memset(irp, 0, sizeof(struct irp) +
		       sizeof(struct io_stack_location));

		irp->size                   = sizeof(struct irp) +
			sizeof(struct io_stack_location);
		irp->stack_size             = 1;
		irp->stack_pos              = 1;
		irp->user_status            = io_status;
		irp->user_event             = event;
		irp->user_buf               = output_buf;

		stack = (struct io_stack_location *)(irp+1);
		irp->current_stack_location = stack+1;

		stack->params.ioctl.code            = ioctl;
		stack->params.ioctl.input_buf_len   = input_buf_len;
		stack->params.ioctl.output_buf_len  = output_buf_len;
		stack->params.ioctl.type3_input_buf = input_buf;
		stack->dev_obj                      = dev_obj;

		stack->major_fn = (internal_ioctl)?
			IRP_MJ_INTERNAL_DEVICE_CONTROL: IRP_MJ_DEVICE_CONTROL;
	}

	TRACEEXIT3(return irp);
}

_FASTCALL static void 
IofCompleteRequest(int dummy, char prio_boost, struct irp *irp)
{
	UNIMPL();
}

STDCALL unsigned char
IoCancelIrp(struct irp *irp)
{
	struct io_stack_location *stack = irp->current_stack_location-1;
	int free_irp = 1;
	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;

	TRACEENTER3("irp = %p", irp);

	wrap_spin_lock(&cancel_lock);
	irp->pending_returned = 1;
	irp->cancel = 1;
	cancel_routine = irp->cancel_routine;
	irp->cancel_routine = NULL;
	wrap_spin_unlock(&cancel_lock);

	if (!cancel_routine)
		TRACEEXIT3(return 0);

	cancel_routine(stack->dev_obj, irp);

	if ((stack->completion_handler) &&
	    (stack->control & CALL_ON_CANCEL)) {
		DBGTRACE3("calling %p", stack->completion_handler);
		local_bh_disable();
		preempt_disable();
		if (stack->completion_handler(stack->dev_obj, irp,
		                              stack->handler_arg) ==
		    STATUS_MORE_PROCESSING_REQUIRED)
			free_irp = 0;
		preempt_enable();
		local_bh_enable();
	}

	/* To-Do: what about IRP_DEALLOCATE_BUFFER...? */
	if (free_irp) {
		DBGTRACE("freeing irp %p", irp);
		kfree(irp);
	}

	TRACEEXIT3(return 1);
}

STDCALL static void IoFreeIrp(struct irp *irp)
{
	TRACEENTER3("irp = %p", irp);

	kfree(irp);

	TRACEEXIT3(return);
}

_FASTCALL static unsigned long IofCallDriver(int dummy, struct irp *irp,
                                             struct device_object *dev_obj)
{
	struct io_stack_location *stack = irp->current_stack_location-1;
	unsigned long ret = STATUS_NOT_SUPPORTED;
	unsigned long result;


	TRACEENTER3("dev_obj = %p, irp = %p, major_fn = %x, ioctl = %lx",
		dev_obj, irp, stack->major_fn, stack->params.ioctl.code);

	if (stack->major_fn == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
		switch (stack->params.ioctl.code) {
			case IOCTL_INTERNAL_USB_SUBMIT_URB:
				ret = usb_submit_nt_urb(dev_obj->device.usb,
					stack->params.generic.arg1, irp);
				break;

			case IOCTL_INTERNAL_USB_RESET_PORT:
				ret = usb_reset_port(dev_obj->device.usb);
				break;

			default:
				ERROR("ioctl %08lX NOT IMPLEMENTED!\n",
					stack->params.ioctl.code);
		}
	} else
		ERROR("major_fn %08X NOT IMPLEMENTED!\n", stack->major_fn);

	if (ret == STATUS_PENDING) {
		stack->control |= IS_PENDING;
		TRACEEXIT3(return ret);
	} else {
		irp->io_status.status = ret;
		if (irp->user_status)
			irp->user_status->status = ret;

		if ((stack->completion_handler) &&
		    ((((ret == 0) && (stack->control & CALL_ON_SUCCESS)) ||
		      ((ret != 0) && (stack->control & CALL_ON_ERROR))))) {
			DBGTRACE3("calling %p", stack->completion_handler);

			result = stack->completion_handler(stack->dev_obj, irp,
				stack->handler_arg);
			if (result == STATUS_MORE_PROCESSING_REQUIRED)
				TRACEEXIT3(return ret);
		}

		if (irp->user_event) {
			DBGTRACE3("setting event %p", irp->user_event);
			NdisSetEvent((struct ndis_event *)irp->user_event);
		}
	}

	/* To-Do: what about IRP_DEALLOCATE_BUFFER...? */
	DBGTRACE3("freeing irp %p", irp);
	kfree(irp);

	TRACEEXIT3(return ret);
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

STDCALL static unsigned long
PsCreateSystemThread(void **phandle, unsigned long access, void *obj_attr,
                     void *process, void *client_id,
                     void (*start_routine)(void *) STDCALL, void *context)
{
	struct trampoline_context *ctx;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	int pid;
#endif

	TRACEENTER2("phandle = %p, access = %lu, obj_attr = %p, process = %p, "
	            "client_id = %p, start_routine = %p, context = %p",
	            phandle, access, obj_attr, process, client_id,
	            start_routine, context);

	ctx = kmalloc(sizeof(struct trampoline_context), GFP_KERNEL);
	if (!ctx)
		TRACEEXIT2(return STATUS_RESOURCES);
	ctx->start_routine = start_routine;
	ctx->context       = context;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	pid = kernel_thread(kthread_trampoline, ctx,
		CLONE_FS|CLONE_FILES|CLONE_SIGHAND);
	DBGTRACE2("pid = %d", pid);
	if (pid < 0) {
		kfree(ctx);
		TRACEEXIT2(return STATUS_FAILURE);
	}
	*phandle = find_task_by_pid(pid);
	DBGTRACE2("*phandle = %p", *phandle);
#else
	*phandle = kthread_run(kthread_trampoline, ctx, "ndiswrapper");
	DBGTRACE2("*phandle = %p", *phandle);
	if (IS_ERR(*phandle)) {
		kfree(ctx);
		TRACEEXIT2(return STATUS_FAILURE);
	}
#endif

	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL static void *KeGetCurrentThread(void)
{
	void *thread = get_current();

	TRACEENTER2("current thread = %p", thread);
	return thread;
}

STDCALL static long KeSetPriorityThread(void *thread, long priority)
{
	long old_prio;

	TRACEENTER2("thread = %p, priority = %ld", thread, priority);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	/* FIXME: is there a way to set kernel thread prio on 2.4? */
	old_prio = 1;
#else
	old_prio = 32 - (task_nice((task_t *)thread) + 20);
	set_user_nice((task_t *)thread, (32 - priority) - 20);
#endif

	return old_prio;
}

STDCALL static unsigned long PsTerminateSystemThread(unsigned long status)
{
	TRACEENTER2("status = %ld", status);
	complete_and_exit(NULL, status);
	return 0;
}

_FASTCALL static long
InterlockedDecrement(int dummy1, int dummy2, long *val)
{
	long x;

	TRACEENTER4("%s", "");
	wrap_spin_lock(&atomic_lock);
	(*val)--;
	x = *val;
	wrap_spin_unlock(&atomic_lock);
	TRACEEXIT4(return x);
}

_FASTCALL static long
InterlockedIncrement(int dummy1, int dummy2, long *val)
{
	long x;

	TRACEENTER4("%s", "");
	wrap_spin_lock(&atomic_lock);
	(*val)++;
	x = *val;
	wrap_spin_unlock(&atomic_lock);
	TRACEEXIT4(return x);
}

_FASTCALL static long InterlockedExchange(int dummy, long val, long *target)
{
	long x;

	TRACEENTER4("%s", "");
	wrap_spin_lock(&atomic_lock);
	x = *target;
	*target = val;
	wrap_spin_unlock(&atomic_lock);
	TRACEEXIT4(return x);
}

STDCALL unsigned long 
IoGetDeviceProperty(struct device_object *dev_obj, int dev_property,
                    unsigned long buffer_len, void *buffer,
                    unsigned long *result_len)
{
	TRACEENTER1("dev_obj = %p, dev_property = %d, buffer_len = %d, "
		"buffer = %p, result_len = %d", dev_obj, dev_property,
		buffer_len, buffer, result_len);

return STATUS_FAILURE;
}

STDCALL static void IoReleaseCancelSpinLock(void){UNIMPL();}
STDCALL static void IoDeleteDevice(void){UNIMPL();}
STDCALL static void IoCreateSymbolicLink(void){UNIMPL();}
STDCALL static void MmMapLockedPages(void){UNIMPL();}
STDCALL static void IoCreateDevice(void){UNIMPL();}
STDCALL static void IoDeleteSymbolicLink(void){UNIMPL();}
STDCALL static void MmMapLockedPagesSpecifyCache(void){UNIMPL();}
STDCALL static void MmProbeAndLockPages(void){UNIMPL();}
STDCALL static void MmUnlockPages(void){UNIMPL();}
STDCALL static void IoAllocateMdl(void){UNIMPL();}
STDCALL static void IoFreeMdl(void){UNIMPL();}
STDCALL static void ObfReferenceObject(void){UNIMPL();}
STDCALL static void ObReferenceObjectByHandle(void){UNIMPL();}
STDCALL static void _except_handler3(void){UNIMPL();}

struct wrap_func ntos_wrap_funcs[] =
{
	WRAP_FUNC_ENTRY(DbgBreakPoint),
	WRAP_FUNC_ENTRY(DbgPrint),
	WRAP_FUNC_ENTRY(ExAllocatePoolWithTag),
	WRAP_FUNC_ENTRY(ExDeleteNPagedLookasideList),
	WRAP_FUNC_ENTRY(ExFreePool),
	WRAP_FUNC_ENTRY(ExInitializeNPagedLookasideList),
	WRAP_FUNC_ENTRY(ExInterlockedAddLargeStatistic),
	WRAP_FUNC_ENTRY(ExInterlockedPopEntrySList),
	WRAP_FUNC_ENTRY(ExInterlockedPushEntrySList),
	WRAP_FUNC_ENTRY(InterlockedExchange),
	WRAP_FUNC_ENTRY(IoAllocateMdl),
	WRAP_FUNC_ENTRY(IoBuildSynchronousFsdRequest),
	WRAP_FUNC_ENTRY(IoCreateDevice),
	WRAP_FUNC_ENTRY(IoCreateSymbolicLink),
	WRAP_FUNC_ENTRY(IoDeleteDevice),
	WRAP_FUNC_ENTRY(IoDeleteSymbolicLink),
	WRAP_FUNC_ENTRY(IoFreeMdl),
	WRAP_FUNC_ENTRY(IoIsWdmVersionAvailable),
	WRAP_FUNC_ENTRY(IoReleaseCancelSpinLock),
	WRAP_FUNC_ENTRY(IofCallDriver),
	WRAP_FUNC_ENTRY(IofCompleteRequest),
	WRAP_FUNC_ENTRY(IoBuildDeviceIoControlRequest),
	WRAP_FUNC_ENTRY(IoFreeIrp),
	WRAP_FUNC_ENTRY(IoCancelIrp),
	WRAP_FUNC_ENTRY(IoAllocateIrp),
	WRAP_FUNC_ENTRY(KeAcquireSpinLock),
	WRAP_FUNC_ENTRY(KeCancelTimer),
	WRAP_FUNC_ENTRY(KeClearEvent),
	WRAP_FUNC_ENTRY(KeGetCurrentIrql),
	WRAP_FUNC_ENTRY(KeInitializeDpc),
	WRAP_FUNC_ENTRY(KeInitializeEvent),
	WRAP_FUNC_ENTRY(KeInitializeSpinLock),
	WRAP_FUNC_ENTRY(KeInitializeTimer),
	WRAP_FUNC_ENTRY(KeReleaseSpinLock),
	WRAP_FUNC_ENTRY(KeSetEvent),
	WRAP_FUNC_ENTRY(KeSetTimerEx),
	WRAP_FUNC_ENTRY(KeSetTimer),
	WRAP_FUNC_ENTRY(KeWaitForSingleObject),
	WRAP_FUNC_ENTRY(MmMapIoSpace),
	WRAP_FUNC_ENTRY(MmMapLockedPages),
	WRAP_FUNC_ENTRY(MmMapLockedPagesSpecifyCache),
	WRAP_FUNC_ENTRY(MmProbeAndLockPages),
	WRAP_FUNC_ENTRY(MmUnlockPages),
	WRAP_FUNC_ENTRY(MmUnmapIoSpace),
	WRAP_FUNC_ENTRY(ObReferenceObjectByHandle),
	WRAP_FUNC_ENTRY(ObfReferenceObject),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_UCHAR),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_ULONG),
	WRAP_FUNC_ENTRY(WRITE_REGISTER_USHORT),
	WRAP_FUNC_ENTRY(_except_handler3),
	WRAP_FUNC_ENTRY(PsCreateSystemThread),
	WRAP_FUNC_ENTRY(KeGetCurrentThread),
	WRAP_FUNC_ENTRY(KeSetPriorityThread),
	WRAP_FUNC_ENTRY(PsTerminateSystemThread),
	WRAP_FUNC_ENTRY(InterlockedDecrement),
	WRAP_FUNC_ENTRY(InterlockedIncrement),
	WRAP_FUNC_ENTRY(KeResetEvent),
	WRAP_FUNC_ENTRY(IoGetDeviceProperty),

	{"KeTickCount", (WRAP_FUNC *)&KeTickCount},

	{NULL, NULL}
};
