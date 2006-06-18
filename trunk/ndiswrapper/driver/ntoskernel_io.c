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
#include "wrapndis.h"
#include "usb.h"
#include "loader.h"

extern NT_SPIN_LOCK ntoskernel_lock;
extern NT_SPIN_LOCK irp_cancel_lock;

wstdcall void WRAP_EXPORT(IoAcquireCancelSpinLock)
	(KIRQL *irql)
{
	*irql = nt_spin_lock_irql(&irp_cancel_lock, DISPATCH_LEVEL);
}

wstdcall void WRAP_EXPORT(IoReleaseCancelSpinLock)
	(KIRQL irql)
{
	nt_spin_unlock_irql(&irp_cancel_lock, irql);
}

wstdcall NTSTATUS WRAP_EXPORT(IoGetDeviceProperty)
	(struct device_object *pdo,
	 enum device_registry_property dev_property,
	 ULONG buffer_len, void *buffer, ULONG *result_len)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	struct wrap_device *wd;
	ULONG need;

	IOENTER("dev_obj = %p, dev_property = %d, buffer_len = %u, "
		"buffer = %p, result_len = %p", pdo, dev_property,
		buffer_len, buffer, result_len);

	wd = pdo->reserved;
	switch (dev_property) {
	case DevicePropertyDeviceDescription:
	case DevicePropertyFriendlyName:
	case DevicePropertyDriverKeyName:
		if (wrap_is_pci_bus(wd->dev_bus_type))
			RtlInitAnsiString(&ansi, "PCI");
		else // if (wrap_is_usb_bus(wd->dev_bus_type))
			RtlInitAnsiString(&ansi, "USB");
		need = sizeof(wchar_t) * (ansi.max_length + 1);
		if (buffer_len < need) {
			*result_len = need;
			IOEXIT(return STATUS_BUFFER_TOO_SMALL);
		}
		unicode.max_length = buffer_len;
		unicode.buf = buffer;
		if (RtlAnsiStringToUnicodeString(&unicode, &ansi,
						 FALSE) != STATUS_SUCCESS) {
			*result_len = unicode.length;
			IOEXIT(return STATUS_BUFFER_TOO_SMALL);
		}
		IOEXIT(return STATUS_SUCCESS);
	default:
		WARNING("%d not implemented", dev_property);
		IOEXIT(return STATUS_INVALID_PARAMETER_2);
	}
}

wstdcall int WRAP_EXPORT(IoIsWdmVersionAvailable)
	(UCHAR major, UCHAR minor)
{
	IOENTER("%d, %x", major, minor);
	if (major == 1 &&
	    (minor == 0x30 || // Windows 2003
	     minor == 0x20 || // Windows XP
	     minor == 0x10)) // Windows 2000
		IOEXIT(return 1);
	IOEXIT(return 0);
}

wstdcall BOOLEAN WRAP_EXPORT(IoIs32bitProcess)
	(struct irp *irp)
{
#ifdef CONFIG_X86_64
	return FALSE;
#else
	return TRUE;
#endif
}

wstdcall void WRAP_EXPORT(IoInitializeIrp)
	(struct irp *irp, USHORT size, CCHAR stack_count)
{
	IOENTER("irp: %p, count: %d", irp, stack_count);

	memset(irp, 0, size);
	irp->size = size;
	irp->stack_count = stack_count;
	/* IoAllocateIrp allocates space for one more than requested
	 * stack_count */
	irp->current_location = stack_count + 1;
	IoGetCurrentIrpStackLocation(irp) = IRP_SL(irp, stack_count + 1);
	IOEXIT(return);
}

wstdcall void WRAP_EXPORT(IoReuseIrp)
	(struct irp *irp, NTSTATUS status)
{
	IOENTER("%p, %d", irp, status);
	if (irp) {
		UCHAR alloc_flags;

		alloc_flags = irp->alloc_flags;
		IoInitializeIrp(irp, irp->size, irp->stack_count);
		irp->alloc_flags = alloc_flags;
		irp->io_status.status = status;
	}
	IOEXIT(return);
}

wstdcall struct irp *WRAP_EXPORT(IoAllocateIrp)
	(char stack_count, BOOLEAN charge_quota)
{
	struct irp *irp;
	int irp_size;

	IOENTER("count: %d", stack_count);
	/* driver need not allocate stack location for itself, but we
	 * need to allocate space for it so that driver can set major
	 * function etc. even if stack_count is 0 */
	irp_size = IoSizeOfIrp(stack_count + 1);
	irp = kmalloc(irp_size, GFP_ATOMIC);
	if (irp) {
		IOTRACE("allocated irp %p", irp);
		IoInitializeIrp(irp, irp_size, stack_count);
	}
	IOEXIT(return irp);
}

wstdcall BOOLEAN WRAP_EXPORT(IoCancelIrp)
	(struct irp *irp)
{
	typeof(irp->cancel_routine) cancel_routine;

	/* NB: this function may be called at DISPATCH_LEVEL */
	IOENTER("irp = %p", irp);

	if (!irp)
		return FALSE;
	DUMP_IRP(irp);
	IoAcquireCancelSpinLock(&irp->cancel_irql);
	cancel_routine = xchg(&irp->cancel_routine, NULL);
	IOTRACE("%p", cancel_routine);
	irp->cancel = TRUE;
	if (cancel_routine) {
		struct io_stack_location *irp_sl;
		irp_sl = IoGetCurrentIrpStackLocation(irp);
		IOTRACE("%p, %p", irp_sl, irp_sl->dev_obj);
		/* cancel_routine will release the spin lock */
		if (LIN2WIN2(cancel_routine, irp_sl->dev_obj, irp))
			IOEXIT(return FALSE);
		else
			IOEXIT(return TRUE);
	} else {
		IOTRACE("irp %p not canceled", irp);
		IoReleaseCancelSpinLock(irp->cancel_irql);
		IOEXIT(return FALSE);
	}
}

wstdcall void IoQueueThreadIrp(struct irp *irp)
{
	struct nt_thread *thread;
	KIRQL irql;

	thread = get_current_nt_thread();
	if (thread) {
		IOTRACE("thread: %p, task: %p", thread, thread->task);
		irql = nt_spin_lock_irql(&thread->lock, DISPATCH_LEVEL);
		irp->flags |= IRP_SYNCHRONOUS_API;
		InsertTailList(&thread->irps, &irp->threads);
		IoIrpThread(irp) = thread;
		nt_spin_unlock_irql(&thread->lock, irql);
	} else
		IoIrpThread(irp) = NULL;
}

wstdcall void IoDequeueThreadIrp(struct irp *irp)
{
	struct nt_thread *thread;
	KIRQL irql;

	thread = IoIrpThread(irp);
	if (thread) {
		irql = nt_spin_lock_irql(&thread->lock, DISPATCH_LEVEL);
		RemoveEntryList(&irp->threads);
		nt_spin_unlock_irql(&thread->lock, irql);
	}
}

wstdcall void WRAP_EXPORT(IoFreeIrp)
	(struct irp *irp)
{
	IOENTER("irp = %p", irp);
	if (irp->flags & IRP_SYNCHRONOUS_API)
		IoDequeueThreadIrp(irp);
	kfree(irp);

	IOEXIT(return);
}

wstdcall struct irp *WRAP_EXPORT(IoBuildAsynchronousFsdRequest)
	(ULONG major_fn, struct device_object *dev_obj, void *buffer,
	 ULONG length, LARGE_INTEGER *offset,
	 struct io_status_block *user_status)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	IOENTER("%p", dev_obj);
	if (!dev_obj)
		IOEXIT(return NULL);
	irp = IoAllocateIrp(dev_obj->stack_count, FALSE);
	if (irp == NULL) {
		WARNING("couldn't allocate irp");
		IOEXIT(return NULL);
	}

	irp_sl = IoGetNextIrpStackLocation(irp);
	irp_sl->major_fn = major_fn;
	IOTRACE("major_fn: %d", major_fn);
	irp_sl->minor_fn = 0;
	irp_sl->flags = 0;
	irp_sl->control = 0;
	irp_sl->dev_obj = dev_obj;
	irp_sl->file_obj = NULL;
	irp_sl->completion_routine = NULL;

	if (dev_obj->flags & DO_DIRECT_IO) {
		irp->mdl = IoAllocateMdl(buffer, length, FALSE, FALSE, irp);
		if (irp->mdl == NULL) {
			IoFreeIrp(irp);
			return NULL;
		}
		MmProbeAndLockPages(irp->mdl, KernelMode,
				    major_fn == IRP_MJ_WRITE ?
				    IoReadAccess : IoWriteAccess);
		IOTRACE("mdl: %p", irp->mdl);
	} else if (dev_obj->flags & DO_BUFFERED_IO) {
		irp->associated_irp.system_buffer = buffer;
		irp->flags = IRP_BUFFERED_IO;
		irp->mdl = NULL;
		IOTRACE("buffer: %p", buffer);
	}
	if (major_fn == IRP_MJ_READ) {
		irp_sl->params.read.length = length;
		irp_sl->params.read.byte_offset = *offset;
	} else if (major_fn == IRP_MJ_WRITE) {
		irp_sl->params.write.length = length;
		irp_sl->params.write.byte_offset = *offset;
	}
	irp->user_status = user_status;
	IOTRACE("irp: %p", irp);
	return irp;
}

wstdcall struct irp *WRAP_EXPORT(IoBuildSynchronousFsdRequest)
	(ULONG major_fn, struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset, struct nt_event *event,
	 struct io_status_block *user_status)
{
	struct irp *irp;

	irp = IoBuildAsynchronousFsdRequest(major_fn, dev_obj, buf, length,
					    offset, user_status);
	if (irp == NULL)
		return NULL;
	irp->user_event = event;
	IoQueueThreadIrp(irp);
	return irp;
}

wstdcall struct irp *WRAP_EXPORT(IoBuildDeviceIoControlRequest)
	(ULONG ioctl, struct device_object *dev_obj,
	 void *input_buf, ULONG input_buf_len, void *output_buf,
	 ULONG output_buf_len, BOOLEAN internal_ioctl,
	 struct nt_event *event, struct io_status_block *io_status)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	IOENTER("%p", dev_obj);
	if (!dev_obj)
		IOEXIT(return NULL);
	irp = IoAllocateIrp(dev_obj->stack_count, FALSE);
	if (irp == NULL) {
		WARNING("couldn't allocate irp");
		return NULL;
	}
	irp->user_status = io_status;
	irp->user_event = event;
	irp->user_buf = output_buf;
	irp->associated_irp.system_buffer = input_buf;

	irp_sl = IoGetNextIrpStackLocation(irp);
	irp_sl->params.dev_ioctl.code = ioctl;
	irp_sl->params.dev_ioctl.input_buf_len = input_buf_len;
	irp_sl->params.dev_ioctl.output_buf_len = output_buf_len;
	irp_sl->dev_obj = dev_obj;
	irp_sl->major_fn = (internal_ioctl) ?
		IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;
	irp_sl->minor_fn = 0;
	irp_sl->flags = 0;
	irp_sl->file_obj = NULL;
	irp_sl->completion_routine = NULL;
	IoQueueThreadIrp(irp);

	IOTRACE("irp: %p", irp);
	IOEXIT(return irp);
}

wfastcall NTSTATUS WRAP_EXPORT(IofCallDriver)
	(struct device_object *dev_obj, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	NTSTATUS status;
	driver_dispatch_t *major_func;
	struct driver_object *drv_obj;

	IoSetNextIrpStackLocation(irp);
	DUMP_IRP(irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	drv_obj = dev_obj->drv_obj;
	irp_sl->dev_obj = dev_obj;
	IOTRACE("drv_obj: %p", drv_obj);
	major_func = drv_obj->major_func[irp_sl->major_fn];
	IOTRACE("major_func: %p, dev_obj: %p", major_func, dev_obj);
	/* TODO: Linux functions must be called natively */
	if (major_func)
		status = LIN2WIN2(major_func, dev_obj, irp);
	else {
		ERROR("major_function %d is not implemented",
		      irp_sl->major_fn);
		status = STATUS_NOT_SUPPORTED;
	}
	IOEXIT(return status);
}

wfastcall void WRAP_EXPORT(IofCompleteRequest)
	(struct irp *irp, CHAR prio_boost)
{
	NTSTATUS status;
	struct io_stack_location *irp_sl;
	struct mdl *mdl;

#ifdef IO_DEBUG
	DUMP_IRP(irp);
	if (irp->io_status.status == STATUS_PENDING) {
		ERROR("invalid irp: %p, STATUS_PENDING", irp);
		return;
	}
	if (irp->current_location < 0) {
		ERROR("invalid irp: %p, %d", irp, irp->current_location);
		return;
	}
#endif
	for (irp_sl = IoGetCurrentIrpStackLocation(irp);
	     irp->current_location <= irp->stack_count; irp_sl++) {
		struct device_object *dev_obj;

		if (irp_sl->control & SL_PENDING_RETURNED)
			irp->pending_returned = TRUE;

		/* current_location and dev_obj must be same as when
		 * driver called IoSetCompletionRoutine, which sets
		 * completion routine at next (lower) location, which
		 * is what we are going to call below; so we set
		 * current_location and dev_obj for the previous
		 * (higher) location */
		IoSkipCurrentIrpStackLocation(irp);

		if (irp->current_location <= irp->stack_count)
			dev_obj = IoGetCurrentIrpStackLocation(irp)->dev_obj;
		else
			dev_obj = NULL;

		if (irp_sl->completion_routine &&
		    ((irp->io_status.status == STATUS_SUCCESS &&
		       irp_sl->control & SL_INVOKE_ON_SUCCESS) ||
		      (irp->io_status.status != STATUS_SUCCESS &&
		       irp_sl->control & SL_INVOKE_ON_ERROR) ||
		      (irp->cancel == TRUE &&
		       irp_sl->control & SL_INVOKE_ON_CANCEL))) {
			IOTRACE("calling completion_routine at: %p, %p",
				irp_sl->completion_routine, irp_sl->context);
			status = LIN2WIN3(irp_sl->completion_routine,
					  dev_obj, irp, irp_sl->context);
			IOTRACE("status: %08X", status);
			if (status == STATUS_MORE_PROCESSING_REQUIRED)
				IOEXIT(return);
		} else {
			/* propagate pending status to next irp_sl */
			if (irp->current_location <= irp->stack_count &&
			    irp->pending_returned == TRUE)
				IoMarkIrpPending(irp);
		}
	}

	if (irp->user_status) {
		irp->user_status->status = irp->io_status.status;
		irp->user_status->info = irp->io_status.info;
	}

	if (irp->user_event) {
		IOTRACE("setting event %p", irp->user_event);
		KeSetEvent(irp->user_event, prio_boost, FALSE);
	}

	IOTRACE("freeing irp %p", irp);
	if (irp->associated_irp.system_buffer &&
	    (irp->flags & IRP_DEALLOCATE_BUFFER))
		ExFreePool(irp->associated_irp.system_buffer);
	else {
		while ((mdl = irp->mdl)) {
			irp->mdl = mdl->next;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
		}
	}
	IoFreeIrp(irp);
	IOEXIT(return);
}

/* IRP functions are called as Windows functions. For 64-bit, this
 * means arguments are in rcx, rdx etc., but Linux functions expect
 * them in rdi, rsi etc. So we need to put arguments back correctly
 * before touching arguments. We also assume that all arguments are
 * pointers (or register width). */

wstdcall NTSTATUS IoPassIrpDown(struct device_object *dev_obj,
			       struct irp *irp)
{
	WIN2LIN2(dev_obj, irp);

	IoSkipCurrentIrpStackLocation(irp);
	IOEXIT(return IoCallDriver(dev_obj, irp));
}


/* called as Windows function, so call WIN2LIN3 before accessing
 * arguments */
wstdcall NTSTATUS IoIrpSyncComplete(struct device_object *dev_obj,
				   struct irp *irp, void *context)
{
	WIN2LIN3(dev_obj, irp, context);

	if (irp->pending_returned == TRUE)
		KeSetEvent(context, IO_NO_INCREMENT, FALSE);
	IOEXIT(return STATUS_MORE_PROCESSING_REQUIRED);
}

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS IoSyncForwardIrp(struct device_object *dev_obj,
				  struct irp *irp)
{
	struct nt_event event;
	NTSTATUS status;

	WIN2LIN2(dev_obj, irp);

	IoCopyCurrentIrpStackLocationToNext(irp);
	KeInitializeEvent(&event, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(irp, IoIrpSyncComplete, &event,
			       TRUE, TRUE, TRUE);
	status = IoCallDriver(dev_obj, irp);
	IOTRACE("%08X", status);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE,
				      NULL);
		status = irp->io_status.status;
	}
	IOTRACE("%08X", status);
	IOEXIT(return status);
}

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS IoAsyncForwardIrp(struct device_object *dev_obj,
				   struct irp *irp)
{
	NTSTATUS status;

	WIN2LIN2(dev_obj, irp);

	IoCopyCurrentIrpStackLocationToNext(irp);
	status = IoCallDriver(dev_obj, irp);
	IOEXIT(return status);
}

/* called as Windows function, so call WIN2LIN2 before accessing
 * arguments */
wstdcall NTSTATUS IoInvalidDeviceRequest(struct device_object *dev_obj,
					struct irp *irp)
{
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	WIN2LIN2(dev_obj, irp);

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	WARNING("%d:%d not implemented", irp_sl->major_fn, irp_sl->minor_fn);
	irp->io_status.status = STATUS_SUCCESS;
	irp->io_status.info = 0;
	status = irp->io_status.status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	IOEXIT(return status);
}

static irqreturn_t io_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	struct kinterrupt *interrupt = (struct kinterrupt *)data;
	NT_SPIN_LOCK *spinlock;
	BOOLEAN ret;

	if (interrupt->actual_lock)
		spinlock = interrupt->actual_lock;
	else
		spinlock = &interrupt->lock;
	nt_spin_lock(spinlock);
	ret = LIN2WIN2(interrupt->service_routine, interrupt,
		       interrupt->service_context);
	nt_spin_unlock(spinlock);

	if (ret == TRUE)
		return IRQ_HANDLED;
	else
		return IRQ_NONE;
}

wstdcall NTSTATUS WRAP_EXPORT(IoConnectInterrupt)
	(struct kinterrupt *interrupt, PKSERVICE_ROUTINE service_routine,
	 void *service_context, NT_SPIN_LOCK *lock, ULONG vector,
	 KIRQL irql, KIRQL synch_irql, enum kinterrupt_mode interrupt_mode,
	 BOOLEAN shareable, KAFFINITY processor_enable_mask,
	 BOOLEAN floating_save)
{
	IOENTER("");

	interrupt->vector = vector;
	interrupt->processor_enable_mask = processor_enable_mask;
//	nt_spin_lock_init(&interrupt->lock);
	interrupt->actual_lock = lock;
	interrupt->shareable = shareable;
	interrupt->floating_save = floating_save;
	interrupt->service_routine = service_routine;
	interrupt->service_context = service_context;
	InitializeListHead(&interrupt->list);
	interrupt->synch_irql = synch_irql;
	interrupt->interrupt_mode = interrupt_mode;
	if (request_irq(vector, io_irq_th, shareable ? SA_SHIRQ : 0,
			"io_irq", interrupt)) {
		WARNING("request for irq %d failed", vector);
		IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
	}
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall void WRAP_EXPORT(IoDisconnectInterrupt)
	(struct kinterrupt *interrupt)
{
	free_irq(interrupt->vector, interrupt);
}

wstdcall struct mdl *WRAP_EXPORT(IoAllocateMdl)
	(void *virt, ULONG length, BOOLEAN second_buf, BOOLEAN charge_quota,
	 struct irp *irp)
{
	struct mdl *mdl;
	mdl = allocate_init_mdl(virt, length);
	if (!mdl)
		return NULL;
	if (irp) {
		if (second_buf == TRUE) {
			struct mdl *last;

			last = irp->mdl;
			while (last->next)
				last = last->next;
			last->next = mdl;
		} else
			irp->mdl = mdl;
	}
	return mdl;
}

wstdcall void WRAP_EXPORT(IoFreeMdl)
	(struct mdl *mdl)
{
	free_mdl(mdl);
	IOEXIT(return);
}

wstdcall struct io_workitem *WRAP_EXPORT(IoAllocateWorkItem)
	(struct device_object *dev_obj)
{
	struct io_workitem *io_workitem;

	IOENTER("%p", dev_obj);
	io_workitem = kmalloc(sizeof(*io_workitem), GFP_ATOMIC);
	if (!io_workitem)
		IOEXIT(return NULL);
	io_workitem->dev_obj = dev_obj;
	IOEXIT(return io_workitem);
}

wstdcall void WRAP_EXPORT(IoFreeWorkItem)
	(struct io_workitem *io_workitem)
{
	kfree(io_workitem);
	IOEXIT(return);
}

wstdcall void WRAP_EXPORT(IoQueueWorkItem)
	(struct io_workitem *io_workitem, void *func,
	 enum work_queue_type queue_type, void *context)
{
	IOENTER("%p, %p", io_workitem, io_workitem->dev_obj);
	io_workitem->worker_routine = func;
	io_workitem->context = context;
	schedule_ntos_work_item(func, io_workitem->dev_obj, context,
				WORKER_FUNC_WIN);
	IOEXIT(return);
}

wstdcall void WRAP_EXPORT(ExQueueWorkItem)
	(struct io_workitem *io_workitem, enum work_queue_type queue_type)
{
	IOENTER("%p", io_workitem);
	schedule_ntos_work_item(io_workitem->worker_routine,
				io_workitem->dev_obj, io_workitem->context,
				WORKER_FUNC_WIN);
}

wstdcall NTSTATUS WRAP_EXPORT(IoAllocateDriverObjectExtension)
	(struct driver_object *drv_obj, void *client_id, ULONG extlen,
	 void **ext)
{
	struct custom_ext *ce;
	KIRQL irql;

	IOENTER("%p, %p", drv_obj, client_id);
	ce = kmalloc(sizeof(*ce) + extlen, GFP_ATOMIC);
	if (ce == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	IOTRACE("custom_ext: %p", ce);
	ce->client_id = client_id;
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	InsertTailList(&drv_obj->drv_ext->custom_ext, &ce->list);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);

	*ext = (void *)ce + sizeof(*ce);
	IOTRACE("ext: %p", *ext);
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall void *WRAP_EXPORT(IoGetDriverObjectExtension)
	(struct driver_object *drv_obj, void *client_id)
{
	struct custom_ext *ce;
	void *ret;
	KIRQL irql;

	IOENTER("drv_obj: %p, client_id: %p", drv_obj, client_id);
	ret = NULL;
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(ce, &drv_obj->drv_ext->custom_ext, list) {
		if (ce->client_id == client_id) {
			ret = (void *)ce + sizeof(*ce);
			break;
		}
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	IOENTER("ret: %p", ret);
	IOEXIT(return ret);
}

void free_custom_extensions(struct driver_extension *drv_ext)
{
	struct nt_list *ent;
	KIRQL irql;

	IOENTER("%p", drv_ext);
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((ent = RemoveHeadList(&drv_ext->custom_ext)))
		kfree(ent);
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return);
}

wstdcall NTSTATUS WRAP_EXPORT(IoCreateDevice)
	(struct driver_object *drv_obj, ULONG dev_ext_length,
	 struct unicode_string *dev_name, DEVICE_TYPE dev_type,
	 ULONG dev_chars, BOOLEAN exclusive, struct device_object **newdev)
{
	struct device_object *dev;
	struct dev_obj_ext *dev_obj_ext;
	int size;
	struct ansi_string ansi;

	IOENTER("%p, %u, %p", drv_obj, dev_ext_length, dev_name);
	if (dev_name && (RtlUnicodeStringToAnsiString(&ansi, dev_name, TRUE)
			 == STATUS_SUCCESS)) {
		IOTRACE("dev_name: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}

	size = sizeof(*dev) + dev_ext_length + sizeof(*dev_obj_ext);
	dev = allocate_object(size, OBJECT_TYPE_DEVICE, ansi.buf);
	if (!dev)
		IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
	if (dev_ext_length)
		dev->dev_ext = dev + 1;
	else
		dev->dev_ext = NULL;

	dev_obj_ext = ((void *)(dev + 1)) + dev_ext_length;
	dev_obj_ext->dev_obj = dev;
	dev_obj_ext->size = 0;
	dev_obj_ext->type = IO_TYPE_DEVICE;
	dev->dev_obj_ext = dev_obj_ext;

	dev->type = dev_type;
	dev->flags = 0;
	dev->size = sizeof(*dev) + dev_ext_length;
	dev->ref_count = 1;
	dev->attached = NULL;
	dev->stack_count = 1;

	dev->drv_obj = drv_obj;
	dev->next = drv_obj->dev_obj;
	drv_obj->dev_obj = dev;

	dev->align_req = 1;
	dev->characteristics = dev_chars;
	dev->io_timer = NULL;
	KeInitializeEvent(&dev->lock, SynchronizationEvent, TRUE);
	dev->vpb = NULL;

	IOTRACE("dev: %p, ext: %p", dev, dev->dev_ext);
	*newdev = dev;
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(IoCreateUnprotectedSymbolicLink)
	(struct unicode_string *link, struct unicode_string *dev_name)
{
	struct ansi_string ansi;

	IOENTER("%p, %p", dev_name, link);
	if (dev_name && (RtlUnicodeStringToAnsiString(&ansi, dev_name, TRUE) ==
			 STATUS_SUCCESS)) {
		IOTRACE("dev_name: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	if (link && (RtlUnicodeStringToAnsiString(&ansi, link, TRUE) ==
		     STATUS_SUCCESS)) {
		IOTRACE("link: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
//	UNIMPL();
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(IoCreateSymbolicLink)
	(struct unicode_string *link, struct unicode_string *dev_name)
{
	IOEXIT(return IoCreateUnprotectedSymbolicLink(link, dev_name));
}

wstdcall NTSTATUS WRAP_EXPORT(IoDeleteSymbolicLink)
	(struct unicode_string *link)
{
	struct ansi_string ansi;

	IOENTER("%p", link);
	if (link && (RtlUnicodeStringToAnsiString(&ansi, link, TRUE) ==
		     STATUS_SUCCESS)) {
		IOTRACE("dev_name: %s", ansi.buf);
		RtlFreeAnsiString(&ansi);
	}
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall void WRAP_EXPORT(IoDeleteDevice)
	(struct device_object *dev)
{
	IOENTER("%p", dev);
	if (dev == NULL)
		IOEXIT(return);
	IOTRACE("drv_obj: %p", dev->drv_obj);
	if (dev->drv_obj) {
		struct device_object *prev;

		prev = dev->drv_obj->dev_obj;
		IOTRACE("dev_obj: %p", prev);
		if (prev == dev)
			dev->drv_obj->dev_obj = dev->next;
		else if (prev) {
			while (prev->next != dev)
				prev = prev->next;
			prev->next = dev->next;
		}
	}
	ObDereferenceObject(dev);
	IOEXIT(return);
}

wstdcall void WRAP_EXPORT(IoDetachDevice)
	(struct device_object *topdev)
{
	struct device_object *tail;
	KIRQL irql;

	IOENTER("%p", topdev);
	if (!topdev)
		IOEXIT(return);
	tail = topdev->attached;
	if (!tail)
		IOEXIT(return);
	IOTRACE("tail: %p", tail);

	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	topdev->attached = tail->attached;
	IOTRACE("attached:%p", topdev->attached);
	for ( ; tail; tail = tail->attached) {
		IOTRACE("tail:%p", tail);
		tail->stack_count--;
	}
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return);
}

wstdcall struct device_object *WRAP_EXPORT(IoGetAttachedDevice)
	(struct device_object *dev)
{
	struct device_object *top_dev;
	KIRQL irql;

	IOENTER("%p", dev);
	if (!dev)
		IOEXIT(return NULL);
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	top_dev = dev;
	while (top_dev->attached)
		top_dev = top_dev->attached;
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return top_dev);
}

wstdcall struct device_object *WRAP_EXPORT(IoGetAttachedDeviceReference)
	(struct device_object *dev)
{
	struct device_object *top_dev;

	IOENTER("%p", dev);
	if (!dev)
		IOEXIT(return NULL);
	top_dev = IoGetAttachedDevice(dev);
	ObReferenceObject(top_dev);
	IOEXIT(return top_dev);
}

wstdcall struct device_object *WRAP_EXPORT(IoAttachDeviceToDeviceStack)
	(struct device_object *src, struct device_object *tgt)
{
	struct device_object *attached;
	struct dev_obj_ext *src_dev_ext;

	KIRQL irql;

	IOENTER("%p, %p", src, tgt);
	attached = IoGetAttachedDevice(tgt);
	IOTRACE("%p", attached);
	src_dev_ext = src->dev_obj_ext;
	irql = nt_spin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	if (attached)
		attached->attached = src;
	src->attached = NULL;
	src->stack_count = attached->stack_count + 1;
	src_dev_ext->attached_to = attached;
	nt_spin_unlock_irql(&ntoskernel_lock, irql);
	IOTRACE("stack_count: %d -> %d", attached->stack_count,
		src->stack_count);
	IOEXIT(return attached);
}


/* NOTE: Make sure to compile with -freg-struct-return, so gcc will
 * return union in register, like Windows */
wstdcall union power_state WRAP_EXPORT(PoSetPowerState)
	(struct device_object *dev_obj, enum power_state_type type,
	 union power_state state)
{
	IOEXIT(return state);
}

wstdcall NTSTATUS WRAP_EXPORT(PoCallDriver)
	(struct device_object *dev_obj, struct irp *irp)
{
	return IoCallDriver(dev_obj, irp);
}

wstdcall NTSTATUS WRAP_EXPORT(PoRequestPowerIrp)
	(struct device_object *dev_obj, UCHAR minor_fn,
	 union power_state power_state, void *completion_func,
	 void *context, struct irp **pirp)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	DBGTRACE1("%p: stack size: %d", dev_obj, dev_obj->stack_count);
	DBGTRACE1("drv_obj: %p", dev_obj->drv_obj);
	irp = IoAllocateIrp(dev_obj->stack_count, FALSE);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;
	irp_sl = IoGetNextIrpStackLocation(irp);
	irp_sl->major_fn = IRP_MJ_POWER;
	irp_sl->minor_fn = minor_fn;
	if (minor_fn == IRP_MN_WAIT_WAKE)
		irp_sl->params.power.type = SystemPowerState;
	else
		irp_sl->params.power.type = DevicePowerState;
	irp_sl->params.power.state = power_state;
	irp_sl->completion_routine = completion_func;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	*pirp = irp;
	return PoCallDriver(dev_obj, irp);
}

wstdcall void WRAP_EXPORT(PoStartNextPowerIrp)
	(struct irp *irp)
{
	IOENTER("irp = %p", irp);
	IOEXIT(return);
}

wstdcall void WRAP_EXPORT(IoInitializeRemoveLockEx)
	(struct io_remove_lock *lock, ULONG alloc_tag, ULONG max_locked_min,
	 ULONG high_mark, ULONG lock_size)
{
	UNIMPL();
}

wstdcall NTSTATUS WRAP_EXPORT(IoAcquireRemoveLockEx)
	(struct io_remove_lock lock, void *tag, char *file, ULONG line,
	 ULONG lock_size)
{
	UNIMPL();
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(IoReleaseRemoveLockEx)
	(struct io_remove_lock lock, void *tag, ULONG lock_size)
{
	UNIMPL();
	IOEXIT(return STATUS_SUCCESS);
}

wstdcall NTSTATUS WRAP_EXPORT(IoRegisterDeviceInterface)
	(struct device_object *pdo, struct guid *guid_class,
	 struct unicode_string *reference, struct unicode_string *link)
{
	struct ansi_string ansi;

	/* TODO: check if pdo is valid */
	RtlInitAnsiString(&ansi, "ndis");
	TRACEENTER1("pdo: %p, ref: %p, link: %p, %x, %x, %x",
		    pdo, reference, link, guid_class->data1,
		    guid_class->data2, guid_class->data3);
	return RtlAnsiStringToUnicodeString(link, &ansi, TRUE);
}

wstdcall NTSTATUS WRAP_EXPORT(IoSetDeviceInterfaceState)
	(struct unicode_string *link, BOOLEAN enable)
{
	TRACEENTER1("link: %p, enable: %d", link, enable);
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(IoOpenDeviceRegistryKey)
	(struct device_object *dev_obj, ULONG type, ACCESS_MASK mask,
	 void **handle)
{
	TRACEENTER1("dev_obj: %p", dev_obj);
	*handle = dev_obj;
	return STATUS_SUCCESS;
}

wstdcall NTSTATUS WRAP_EXPORT(IoWMIRegistrationControl)
	(struct device_object *dev_obj, ULONG action)
{
	TRACEENTER2("%p, %d", dev_obj, action);
	TRACEEXIT2(return STATUS_SUCCESS);
}

wstdcall void WRAP_EXPORT(IoInvalidateDeviceRelations)
	(struct device_object *dev_obj, enum device_relation_type type)
{
	INFO("%p, %d", dev_obj, type);
	UNIMPL();
}

wstdcall void WRAP_EXPORT(IoInvalidateDeviceState)
	(struct device_object *pdo)
{
	INFO("%p", pdo);
	UNIMPL();
}

#include "ntoskernel_io_exports.h"
