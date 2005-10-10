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
#include "wrapper.h"
#include "usb.h"

extern KSPIN_LOCK ntoskernel_lock;
extern KSPIN_LOCK irp_cancel_lock;
extern struct nt_list object_list;

extern struct work_struct io_work;
extern struct nt_list io_workitem_list;
extern KSPIN_LOCK io_workitem_list_lock;

extern KSPIN_LOCK irp_cancel_lock;

STDCALL void WRAP_EXPORT(IoAcquireCancelSpinLock)
	(KIRQL *irql)
{
	*irql = kspin_lock_irql(&irp_cancel_lock, DISPATCH_LEVEL);
}

STDCALL void WRAP_EXPORT(IoReleaseCancelSpinLock)
	(KIRQL irql)
{
	kspin_unlock_irql(&irp_cancel_lock, irql);
}

STDCALL NTSTATUS WRAP_EXPORT(IoGetDeviceProperty)
	(struct device_object *pdo,
	 enum device_registry_property dev_property,
	 ULONG buffer_len, void *buffer, ULONG *result_len)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	struct wrapper_dev *wd;
	char buf[32];

	wd = pdo->reserved;

	IOENTER("dev_obj = %p, dev_property = %d, buffer_len = %u, "
		"buffer = %p, result_len = %p", pdo, dev_property,
		buffer_len, buffer, result_len);

	switch (dev_property) {
	case DevicePropertyDeviceDescription:
		if (buffer_len > 0 && buffer) {
			*result_len = sizeof(int);
			memset(buffer, 0xFF, *result_len);
			IOEXIT(return STATUS_SUCCESS);
		} else {
			*result_len = sizeof(int);
			IOEXIT(return STATUS_SUCCESS);
		}
		break;

	case DevicePropertyFriendlyName:
		if (buffer_len > 0 && buffer) {
			ansi.len = snprintf(buf, sizeof(buf), "%d",
					    wd->dev.usb.udev->devnum);
			ansi.buf = buf;
			ansi.len = strlen(ansi.buf);
			if (ansi.len <= 0) {
				*result_len = 0;
				IOEXIT(return STATUS_BUFFER_TOO_SMALL);
			}
			ansi.buflen = ansi.len;
			unicode.buf = buffer;
			unicode.buflen = buffer_len;
			IOTRACE("unicode.buflen = %d, ansi.len = %d",
				unicode.buflen, ansi.len);
			if (RtlAnsiStringToUnicodeString(&unicode, &ansi, 0)) {
				*result_len = 0;
				IOEXIT(return STATUS_BUFFER_TOO_SMALL);
			} else {
				*result_len = unicode.len;
				IOEXIT(return STATUS_SUCCESS);
			}
		} else {
			ansi.len = snprintf(buf, sizeof(buf), "%d",
					    wd->dev.usb.udev->devnum);
			*result_len = 2 * (ansi.len + 1);
			IOEXIT(return STATUS_BUFFER_TOO_SMALL);
		}
		break;

	case DevicePropertyDriverKeyName:
//		ansi.buf = wd->driver->name;
		ansi.buf = buf;
		ansi.len = strlen(ansi.buf);
		ansi.buflen = ansi.len;
		if (buffer_len > 0 && buffer) {
			unicode.buf = buffer;
			unicode.buflen = buffer_len;
			if (RtlAnsiStringToUnicodeString(&unicode, &ansi, 0)) {
				*result_len = 0;
				IOEXIT(return STATUS_BUFFER_TOO_SMALL);
			} else {
				*result_len = unicode.len;
				IOEXIT(return STATUS_SUCCESS);
			}
		} else {
				*result_len = 2 * (strlen(buf) + 1);
				IOEXIT(return STATUS_SUCCESS);
		}
		break;
	default:
		IOEXIT(return STATUS_INVALID_PARAMETER_2);
	}
}

STDCALL int WRAP_EXPORT(IoIsWdmVersionAvailable)
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

STDCALL BOOLEAN WRAP_EXPORT(IoIs32bitProcess)
	(struct irp *irp)
{
#ifdef CONFIG_X86_64
	return FALSE;
#else
	return TRUE;
#endif
}

STDCALL void WRAP_EXPORT(IoInitializeIrp)
	(struct irp *irp, USHORT size, CCHAR stack_size)
{
	IOENTER("irp = %p, stack_size = %d", irp, stack_size);

	memset(irp, 0, size);
	irp->size = size;
	irp->stack_count = stack_size;
	irp->current_location = stack_size + 1;
	IoGetCurrentIrpStackLocation(irp) = IRP_SL(irp, (stack_size + 1));
	IOEXIT(return);
}

STDCALL void WRAP_EXPORT(IoReuseIrp)
	(struct irp *irp, NTSTATUS status)
{
	IOENTER("irp = %p, status = %d", irp, status);
	if (irp) {
		UCHAR alloc_flags;

		alloc_flags = irp->alloc_flags;
		IoInitializeIrp(irp, irp->size, irp->stack_count);
		irp->alloc_flags = alloc_flags;
		irp->io_status.status = status;
	}
	IOEXIT(return);
}

STDCALL struct irp *WRAP_EXPORT(IoAllocateIrp)
	(char stack_size, BOOLEAN charge_quota)
{
	struct irp *irp;
	int irp_size;

	IOENTER("stack_size = %d, charge_quota = %d",
		stack_size, charge_quota);

	irp_size = IoSizeOfIrp(stack_size + 1);
	irp = kmalloc(irp_size, GFP_ATOMIC);
	if (irp) {
		IOTRACE("allocated irp %p", irp);
		IoInitializeIrp(irp, irp_size, stack_size);
	}
#if 0
	DBG_BLOCK() {
		int i;
		for (i = 0; i < stack_size; i++)
			INFO("stack %d at %p", i, IRP_SL(irp, i));
	}
#endif

	IOEXIT(return irp);
}

STDCALL BOOLEAN WRAP_EXPORT(IoCancelIrp)
	(struct irp *irp)
{
	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;

	/* NB: this function may be called at DISPATCH_LEVEL */
	IOENTER("irp = %p", irp);

	if (!irp)
		return FALSE;
	DUMP_IRP(irp);
	IoAcquireCancelSpinLock(&irp->cancel_irql);
	cancel_routine = irp->cancel_routine;
	irp->cancel_routine = NULL;
	irp->cancel = TRUE;
	if (cancel_routine) {
		struct io_stack_location *irp_sl;

		irp_sl = IoGetCurrentIrpStackLocation(irp);
		/* cancel_routine will release the spin lock */
		cancel_routine(irp_sl->dev_obj, irp);
		IOEXIT(return TRUE);
	} else {
		IoReleaseCancelSpinLock(irp->cancel_irql);
		IOEXIT(return FALSE);
	}
}

STDCALL void IoQueueThreadIrp(struct irp *irp)
{
	struct kthread *kthread;
	KIRQL irql;

	kthread = KeGetCurrentThread();
	if (!kthread) {
		WARNING("couldn't find thread for irp: %p, task: %p, pid: %d",
			irp, get_current(), get_current()->pid);
		IoIrpThread(irp) = NULL;
		return;
	}
	IOTRACE("kthread: %p, task: %p", kthread, kthread->task);
	irql = kspin_lock_irql(&kthread->lock, DISPATCH_LEVEL);
	irp->flags |= IRP_SYNCHRONOUS_API;
	InsertTailList(&kthread->irps, &irp->threads);
	IoIrpThread(irp) = kthread;
	kspin_unlock_irql(&kthread->lock, irql);
}

STDCALL void IoDequeueThreadIrp(struct irp *irp)
{
	struct kthread *kthread;
	KIRQL irql;

	kthread = IoIrpThread(irp);
	if (kthread) {
		irql = kspin_lock_irql(&kthread->lock, DISPATCH_LEVEL);
		RemoveEntryList(&irp->threads);
		kspin_unlock_irql(&kthread->lock, irql);
	}
}

STDCALL void WRAP_EXPORT(IoFreeIrp)
	(struct irp *irp)
{
	IOENTER("irp = %p", irp);
	if (irp->flags & IRP_SYNCHRONOUS_API)
		IoDequeueThreadIrp(irp);
	kfree(irp);

	IOEXIT(return);
}

STDCALL struct irp *WRAP_EXPORT(IoBuildAsynchronousFsdRequest)
	(ULONG major_fn, struct device_object *dev_obj, void *buffer,
	 ULONG length, LARGE_INTEGER *offset,
	 struct io_status_block *status)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	IOENTER("%p", dev_obj);
	irp = IoAllocateIrp(dev_obj->stack_size, FALSE);
	if (irp == NULL)
		return NULL;

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
		IOTRACE("irp %p with DO_DIRECT_IO", irp);
		irp->mdl = IoAllocateMdl(buffer, length, FALSE, FALSE, irp);
		if (irp->mdl == NULL) {
			IoFreeIrp(irp);
			return NULL;
		}
	} else if (dev_obj->flags & DO_BUFFERED_IO) {
		IOTRACE("irp %p with DO_BUFFERED_IO", irp);
		irp->associated_irp.system_buffer =
			ExAllocatePoolWithTag(NonPagedPool, length, 0);
		if (irp->associated_irp.system_buffer == NULL) {
			IoFreeIrp(irp);
			return NULL;
		}
		irp->flags |= IRP_ASSOCIATED_IRP;
		memcpy(irp->associated_irp.system_buffer, buffer, length);
		irp->user_status = status;
		irp->user_buf = buffer;
	}
	if (major_fn == IRP_MJ_READ) {
		irp_sl->params.read.length = length;
		irp_sl->params.read.byte_offset = *offset;
	} else if (major_fn == IRP_MJ_WRITE) {
		irp_sl->params.write.length = length;
		irp_sl->params.write.byte_offset = *offset;
	}
	IOTRACE("irp: %p", irp);
	return irp;
}

STDCALL struct irp *WRAP_EXPORT(IoBuildSynchronousFsdRequest)
	(ULONG major_fn, struct device_object *dev_obj, void *buf,
	 ULONG length, LARGE_INTEGER *offset, struct kevent *event,
	 struct io_status_block *status)
{
	struct irp *irp;

	irp = IoBuildAsynchronousFsdRequest(major_fn, dev_obj, buf, length,
					    offset, status);
	if (irp == NULL)
		return NULL;
	irp->user_event = event;
	IoQueueThreadIrp(irp);
	return irp;
}

STDCALL struct irp *WRAP_EXPORT(IoBuildDeviceIoControlRequest)
	(ULONG ioctl, struct device_object *dev_obj,
	 void *input_buf, ULONG input_buf_len, void *output_buf,
	 ULONG output_buf_len, BOOLEAN internal_ioctl,
	 struct kevent *event, struct io_status_block *io_status)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	IOENTER("");

	irp = IoAllocateIrp(dev_obj->stack_size, FALSE);
	if (irp) {
		irp->user_status = io_status;
		irp->user_event = event;
		irp->user_buf = output_buf;
		irp->associated_irp.system_buffer = input_buf;

		irp_sl = IoGetNextIrpStackLocation(irp);
		irp_sl->params.ioctl.code = ioctl;
		irp_sl->params.ioctl.input_buf_len = input_buf_len;
		irp_sl->params.ioctl.output_buf_len = output_buf_len;
		irp_sl->dev_obj = dev_obj;
		irp_sl->major_fn = (internal_ioctl) ?
			IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;
		irp_sl->minor_fn = 0;
		irp_sl->flags = 0;
		irp_sl->file_obj = NULL;
		irp_sl->completion_routine = NULL;
	}

	IOTRACE("irp: %p", irp);
	IoQueueThreadIrp(irp);
	IOEXIT(return irp);
}

_FASTCALL NTSTATUS WRAP_EXPORT(IofCallDriver)
	(FASTCALL_DECL_2(struct device_object *dev_obj, struct irp *irp))
{
	struct io_stack_location *irp_sl;
	NTSTATUS res;
	driver_dispatch_t *major_func;
	struct driver_object *drv_obj;

	DUMP_IRP(irp);

	drv_obj = dev_obj->drv_obj;
	IOTRACE("drv_obj: %p", drv_obj);
	IoSetNextIrpStackLocation(irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);

	irp_sl->dev_obj = dev_obj;
	major_func = drv_obj->major_func[irp_sl->major_fn];
	IOTRACE("major_func: %p", major_func);
	if (major_func)
		res = (*major_func)(dev_obj, irp);
	else {
		ERROR("major_function %d is not implemented",
		      irp_sl->major_fn);
		res = STATUS_NOT_SUPPORTED;
	}
	IOEXIT(return res);
}

_FASTCALL void WRAP_EXPORT(IofCompleteRequest)
	(FASTCALL_DECL_2(struct irp *irp, CHAR prio_boost))
{
	NTSTATUS res;
	struct io_stack_location *irp_sl;
	struct mdl *mdl;

	DUMP_IRP(irp);
	if (irp->io_status.status == STATUS_PENDING) {
		ERROR("invalid irp: %p, STATUS_PENDING", irp);
		return;
	}

	if (irp->current_location < 0) {
		ERROR("invalid irp: %p, %d", irp, irp->current_location);
		return;
	}

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	IoSkipCurrentIrpStackLocation(irp);

	while (irp->current_location <= (irp->stack_count + 1)) {
		struct device_object *dev_obj;

		if (irp_sl->control & SL_PENDING_RETURNED)
			irp->pending_returned = TRUE;

		if (irp->current_location <= irp->stack_count)
			dev_obj = IoGetCurrentIrpStackLocation(irp)->dev_obj;
		else
			dev_obj = NULL;

		if (irp_sl->completion_routine &&
		    ((irp->io_status.status == STATUS_SUCCESS &&
		       irp_sl->control & CALL_ON_SUCCESS) ||
		      (irp->io_status.status != STATUS_SUCCESS &&
		       irp_sl->control & CALL_ON_ERROR) ||
		      (irp->cancel && (irp_sl->control & CALL_ON_CANCEL)))) {
			IOTRACE("calling completion_routine at: %p",
				irp_sl->completion_routine);
			res = LIN2WIN3(irp_sl->completion_routine, dev_obj,
				       irp, irp_sl->context);
			if (res == STATUS_MORE_PROCESSING_REQUIRED)
				IOEXIT(return);
			IOTRACE("completion routine returned");
		} else {
			if (irp->current_location <= irp->stack_count &&
			    irp->pending_returned)
				IoMarkIrpPending(irp);
		}
		IoSkipCurrentIrpStackLocation(irp);
		irp_sl++;
	}

	if (irp->user_status) {
		irp->user_status->status = irp->io_status.status;
		irp->user_status->status_info = irp->io_status.status_info;
	}

	if (irp->user_event) {
		IOTRACE("setting event %p", irp->user_event);
		KeSetEvent(irp->user_event, prio_boost, FALSE);
	}

	IOTRACE("freeing irp %p", irp);
	while ((mdl = irp->mdl)) {
		irp->mdl = mdl->next;
		IoFreeMdl(mdl);
	}
	if (irp->flags & IRP_DEALLOCATE_BUFFER)
		ExFreePool(irp->associated_irp.system_buffer);
	IoFreeIrp(irp);
	IOEXIT(return);
}

STDCALL NTSTATUS
pdoDispatchInternalDeviceControl(struct device_object *pdo,
				 struct  irp *irp)
{
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	DUMP_IRP(irp);

	if (irp->current_location < 0 ||
	    irp->current_location > irp->stack_count) {
		ERROR("invalid irp: %p, %d, %d", irp, irp->current_location,
		      irp->stack_count);
		irp->io_status.status = STATUS_FAILURE;
		irp->io_status.status_info = 0;
		IOEXIT(return STATUS_FAILURE);
	}
	irp_sl = IoGetCurrentIrpStackLocation(irp);

#ifdef CONFIG_USB
	status = wrap_submit_irp(pdo, irp);
	IOTRACE("status: %08X", status);
	if (status == STATUS_PENDING) {
		/* although as per DDK, we are not supposed to touch
		 * irp when STAUS_PENDING is returned, this irp hasn't
		 * been submitted to usb yet (and not completed), so
		 * it is safe in this case */
		status = wrap_submit_urb(irp);
	}
	if (status != STATUS_PENDING)
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	IOEXIT(return status);
#else
	do {
		union nt_urb *nt_urb;
		status = irp->io_status.status = STATUS_NOT_IMPLEMENTED;
		nt_urb = URB_FROM_IRP(irp);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_NOT_SUPPORTED;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	} while (0)
#endif
}

STDCALL NTSTATUS pdoDispatchDeviceControl(struct device_object *pdo,
					  struct irp *irp)
{
	return pdoDispatchInternalDeviceControl(pdo, irp);
}

STDCALL NTSTATUS IopInvalidDeviceRequest(struct device_object *dev_obj,
					 struct irp *irp)
{
	struct io_stack_location *irp_sl;
	NTSTATUS res;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	WARNING("IRP %d:%d not implemented",
		irp_sl->major_fn, irp_sl->minor_fn);
	irp->io_status.status = STATUS_NOT_IMPLEMENTED;
	irp->io_status.status_info = 0;
	res = irp->io_status.status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return res;
}

STDCALL NTSTATUS IopIrpWaitComplete(struct device_object *dev_obj,
				    struct irp *irp, void *context)
{
	IOTRACE("dev_obj: %p, irp: %p, context: %p",
		dev_obj, irp, context);
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS IopPassIrpDownAndWait(struct device_object *dev_obj,
				       struct irp *irp)
{
	struct wrapper_dev *wd;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	IOENTER("dev_obj: %p, irp: %p", dev_obj, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	IoSetCompletionRoutine(irp, IopIrpWaitComplete, (void *)0x34b9f1,
			       TRUE, TRUE, TRUE);
	wd = dev_obj->reserved;
	status = IoCallDriver(wd->nmb->pdo, irp);
	return status;
}

STDCALL NTSTATUS IopPassIrpDown(struct device_object *dev_obj,
				struct irp *irp)
{
	struct wrapper_dev *wd;
	NTSTATUS status;

	IOENTER("dev_obj: %p, irp: %p", dev_obj, irp);
	IoSkipCurrentIrpStackLocation(irp);
	wd = dev_obj->reserved;
	status = IoCallDriver(wd->nmb->pdo, irp);
	return status;
}

STDCALL NTSTATUS pdoDispatchPnp(struct device_object *pdo,
				struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	NTSTATUS res;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;
	IOTRACE("fn %d:%d, wd: %p", irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		irp->io_status.status = miniport_init(wd);
		break;
	case IRP_MN_STOP_DEVICE:
		miniport_halt(wd);
		irp->io_status.status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_STOP_DEVICE:
		irp->io_status.status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_REMOVE_DEVICE:
		irp->io_status.status = STATUS_SUCCESS;
		break;
	case IRP_MN_REMOVE_DEVICE:
		miniport_halt(wd);
//		free_pdo(wd->nmb->pdo);
		irp->io_status.status = STATUS_SUCCESS;
		break;
	default:
		WARNING("minor_fn: %d not implemented", irp_sl->minor_fn);
		irp->io_status.status = STATUS_FAILURE;
		break;
	}
	irp->io_status.status_info = 0;
	res = irp->io_status.status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return res;
}

STDCALL NTSTATUS pdoDispatchPower(struct device_object *pdo,
				  struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	enum device_power_state state;
	struct pci_dev *pdev;
	NTSTATUS res;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;
	IOTRACE("pdo: %p, fn: %d:%d, wd: %p",
		  pdo, irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_SET_POWER:
		state = irp_sl->params.power.state.device_state;
		pdev = wd->dev.pci;
		if (state == PowerDeviceD0) {
			IOTRACE("resuming device %p", wd);
			irp->io_status.status = STATUS_SUCCESS;
		} else {
			IOTRACE("suspending device %p", wd);
			irp->io_status.status = STATUS_SUCCESS;
		}
		break;
	case IRP_MN_QUERY_POWER:
		irp->io_status.status = STATUS_SUCCESS;
		break;
	default:
		irp->io_status.status = STATUS_SUCCESS;
		ERROR("invalid power irp");
		break;
	}

	irp->io_status.status_info = 0;
	res = irp->io_status.status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return res;
}

STDCALL NTSTATUS fdoDispatchPnp(struct device_object *fdo,
				struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;

	IOENTER("fdo: %p, irp: %p", fdo, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	IOTRACE("irp_sl: %p, handler: %p",
		irp_sl, irp_sl->completion_routine);
	wd = fdo->reserved;
	switch (irp_sl->minor_fn) {
	case IRP_MN_REMOVE_DEVICE:
		/*
		IoSkipCurrentIrpStackLocation(irp);
		IoCallDriver(wd->nmb->pdo, irp);
		free_pdo(wd->nmb->pdo);
		*/
		break;
	case IRP_MN_START_DEVICE:
		break;
	}
	return STATUS_SUCCESS;
}

static irqreturn_t io_irq_th(int irq, void *data, struct pt_regs *pt_regs)
{
	struct kinterrupt *interrupt = (struct kinterrupt *)data;
	KSPIN_LOCK *spinlock;
	BOOLEAN ret;
	KIRQL irql = PASSIVE_LEVEL;

	if (interrupt->actual_lock)
		spinlock = interrupt->actual_lock;
	else
		spinlock = &interrupt->lock;
	if (interrupt->synch_irql >= DISPATCH_LEVEL)
		irql = kspin_lock_irql(spinlock, DISPATCH_LEVEL);
	else
		kspin_lock(spinlock);
	ret = interrupt->service_routine(interrupt,
					 interrupt->service_context);
	if (interrupt->synch_irql >= DISPATCH_LEVEL)
		kspin_unlock_irql(spinlock, irql);
	else
		kspin_unlock(spinlock);

	if (ret == TRUE)
		return IRQ_HANDLED;
	else
		return IRQ_NONE;
}

STDCALL NTSTATUS WRAP_EXPORT(IoConnectInterrupt)
	(struct kinterrupt *interrupt, PKSERVICE_ROUTINE service_routine,
	 void *service_context, KSPIN_LOCK *lock, ULONG vector,
	 KIRQL irql, KIRQL synch_irql, enum kinterrupt_mode interrupt_mode,
	 BOOLEAN shareable, KAFFINITY processor_enable_mask,
	 BOOLEAN floating_save)
{
	IOENTER("");

	interrupt->vector = vector;
	interrupt->processor_enable_mask = processor_enable_mask;
	kspin_lock_init(&interrupt->lock);
	interrupt->actual_lock = lock;
	interrupt->shareable = shareable;
	interrupt->floating_save = floating_save;
	interrupt->service_routine = service_routine;
	interrupt->service_context = service_context;
	InitializeListHead(&interrupt->list);
	interrupt->irql = irql;
	if (synch_irql > DISPATCH_LEVEL)
		interrupt->synch_irql = DISPATCH_LEVEL;
	else
		interrupt->synch_irql = synch_irql;
	interrupt->interrupt_mode = interrupt_mode;
	if (request_irq(vector, io_irq_th, shareable ? SA_SHIRQ : 0,
			"io_irq", interrupt)) {
		WARNING("request for irq %d failed", vector);
		IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
	}
	IOEXIT(return STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(PoStartNextPowerIrp)
	(struct irp *irp)
{
	IOENTER("irp = %p", irp);
	IOEXIT(return);
}

STDCALL void WRAP_EXPORT(IoDisconnectInterrupt)
	(struct kinterrupt *interrupt)
{
	free_irq(interrupt->vector, interrupt);
}

STDCALL struct mdl *WRAP_EXPORT(IoAllocateMdl)
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

STDCALL void WRAP_EXPORT(IoFreeMdl)
	(struct mdl *mdl)
{
	free_mdl(mdl);
	IOEXIT(return);
}

void io_worker(void *data)
{
	struct io_workitem_entry *io_workitem_entry;
	struct io_workitem *io_workitem;
	struct nt_list *cur;

	while (1) {
		KIRQL irql;

		irql = kspin_lock_irql(&io_workitem_list_lock, DISPATCH_LEVEL);
		cur = RemoveHeadList(&io_workitem_list);
		kspin_unlock_irql(&io_workitem_list_lock, irql);
		if (!cur)
			break;
		io_workitem_entry = container_of(cur, struct io_workitem_entry,
						 list);
		io_workitem = io_workitem_entry->io_workitem;
		LIN2WIN2(io_workitem->worker_routine, io_workitem->dev_obj,
			 io_workitem->context);
		kfree(io_workitem_entry);
	}
	return;
}

STDCALL struct io_workitem *WRAP_EXPORT(IoAllocateWorkItem)
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

STDCALL void WRAP_EXPORT(IoFreeWorkItem)
	(struct io_workitem *io_workitem)
{
	kfree(io_workitem);
	IOEXIT(return);
}

STDCALL void WRAP_EXPORT(ExQueueWorkItem)
	(struct io_workitem *io_workitem, enum work_queue_type queue_type)
{
	struct io_workitem_entry *io_workitem_entry;
	KIRQL irql;

	IOENTER("");
	if (io_workitem == NULL) {
		ERROR("io_work_item is NULL; item not queued");
		return;
	}

	io_workitem_entry = kmalloc(sizeof(*io_workitem_entry), GFP_ATOMIC);
	if (!io_workitem_entry) {
		ERROR("couldn't allocate memory; item not queued");
		return;
	}

	io_workitem->type = queue_type;
	io_workitem_entry->io_workitem = io_workitem;

	irql = kspin_lock_irql(&io_workitem_list_lock, DISPATCH_LEVEL);
	InsertTailList(&io_workitem_list, &io_workitem_entry->list);
	kspin_unlock_irql(&io_workitem_list_lock, irql);

	schedule_work(&io_work);
}

STDCALL void WRAP_EXPORT(IoQueueWorkItem)
	(struct io_workitem *io_workitem, void *func,
	 enum work_queue_type queue_type, void *context)
{
	io_workitem->worker_routine = func;
	io_workitem->context = context;

	ExQueueWorkItem(io_workitem, queue_type);
	IOEXIT(return);
}

STDCALL NTSTATUS WRAP_EXPORT(IoAllocateDriverObjectExtension)
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
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	InsertTailList(&drv_obj->drv_ext->custom_ext, &ce->list);
	kspin_unlock_irql(&ntoskernel_lock, irql);

	*ext = (void *)ce + sizeof(*ce);
	IOTRACE("ext: %p", *ext);
	IOEXIT(return STATUS_SUCCESS);
}

STDCALL void *WRAP_EXPORT(IoGetDriverObjectExtension)
	(struct driver_object *drv_obj, void *client_id)
{
	struct custom_ext *ce;
	void *ret;
	KIRQL irql;

	IOENTER("drv_obj: %p, client_id: %p", drv_obj, client_id);
	ret = NULL;
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(ce, &drv_obj->drv_ext->custom_ext, list) {
		if (ce->client_id == client_id) {
			ret = (void *)ce + sizeof(*ce);
			break;
		}
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	IOENTER("ret: %p", ret);
	IOEXIT(return ret);
}

void free_custom_ext(struct driver_extension *drv_ext)
{
	struct nt_list *ent;
	KIRQL irql;

	IOENTER("%p", drv_ext);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((ent = RemoveHeadList(&drv_ext->custom_ext)))
		kfree(ent);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return);
}

STDCALL NTSTATUS WRAP_EXPORT(IoCreateDevice)
	(struct driver_object *drv_obj, ULONG dev_ext_length,
	 struct unicode_string *dev_name, DEVICE_TYPE dev_type,
	 ULONG dev_chars, BOOLEAN exclusive, struct device_object **newdev)
{
	struct device_object *dev;

	IOENTER("%p, %u, %p", drv_obj, dev_ext_length, dev_name);
	dev = ALLOCATE_OBJECT(struct device_object, GFP_KERNEL,
			      OBJECT_TYPE_DEVICE);
	if (!dev)
		IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
	dev->type = dev_type;
	dev->drv_obj = drv_obj;
	dev->flags = 0;
	if (dev_ext_length) {
		dev->dev_ext = ExAllocatePoolWithTag(NonPagedPool,
						     dev_ext_length, 0);
		if (!dev->dev_ext) {
			ObDereferenceObject(dev);
			IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
		}
	} else
		dev->dev_ext = NULL;
	dev->size = sizeof(*dev) + dev_ext_length;
	dev->ref_count = 1;
	dev->attached = NULL;
	dev->next = NULL;
	dev->type = dev_type;
	dev->stack_size = 1;
	dev->align_req = 1;
	dev->characteristics = dev_chars;
	dev->io_timer = NULL;
	KeInitializeEvent(&dev->lock, SynchronizationEvent, TRUE);
	dev->vpb = NULL;
	dev->dev_obj_ext = ExAllocatePoolWithTag(NonPagedPool,
						 sizeof(*(dev->dev_obj_ext)),
						 0);
	if (!dev->dev_obj_ext) {
		if (dev->dev_ext)
			ExFreePool(dev->dev_ext);
		ObDereferenceObject(dev);
		IOEXIT(return STATUS_INSUFFICIENT_RESOURCES);
	}
	dev->dev_obj_ext->type = 0;
	dev->dev_obj_ext->size = sizeof(*dev->dev_obj_ext);
	dev->dev_obj_ext->dev_obj = dev;
	drv_obj->dev_obj = dev;
	if (drv_obj->dev_obj)
		dev->next = drv_obj->dev_obj;
	else
		dev->next = NULL;
	IOTRACE("%p", dev);
	*newdev = dev;
	IOEXIT(return STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(IoDeleteDevice)
	(struct device_object *dev)
{
	IOENTER("%p", dev);
	if (dev == NULL)
		IOEXIT(return);
	if (dev->dev_ext)
		ExFreePool(dev->dev_ext);
	if (dev->dev_obj_ext)
		ExFreePool(dev->dev_obj_ext);
	IOTRACE("drv_obj: %p", dev->drv_obj);
	if (dev->drv_obj) {
		struct device_object *prev;

		prev = dev->drv_obj->dev_obj;
		IOTRACE("dev_obj: %p", prev);
#if 0
		if (prev == dev)
			dev->drv_obj->dev_obj = dev->next;
		else {
			while (prev->next != dev)
				prev = prev->next;
			prev->next = dev->next;
		}
#endif
	}
	ObDereferenceObject(dev);
	IOEXIT(return);
}

STDCALL struct device_object *WRAP_EXPORT(IoGetAttachedDevice)
	(struct device_object *dev)
{
	struct device_object *d;
	KIRQL irql;

	IOENTER("%p", dev);
	if (!dev)
		IOEXIT(return NULL);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	for (d = dev; d->attached; d = d->attached)
		;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return d);
}

STDCALL struct device_object *WRAP_EXPORT(IoGetAttachedDeviceReference)
	(struct device_object *dev)
{
	struct device_object *d;

	IOENTER("%p", dev);
	if (!dev)
		IOEXIT(return NULL);
	d = IoGetAttachedDevice(dev);
	ObReferenceObject(d);
	IOEXIT(return d);
}

STDCALL struct device_object *WRAP_EXPORT(IoAttachDeviceToDeviceStack)
	(struct device_object *src, struct device_object *tgt)
{
	struct device_object *dst;
	KIRQL irql;

	IOENTER("%p, %p", src, tgt);
	dst = IoGetAttachedDevice(tgt);
	IOTRACE("stack_size: %d -> %d", dst->stack_size, src->stack_size);
	IOTRACE("%p", dst);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	if (dst)
		dst->attached = src;
	src->attached = NULL;
	src->stack_size = dst->stack_size + 1;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	IOTRACE("stack_size: %d -> %d", dst->stack_size, src->stack_size);
	IOEXIT(return dst);
}

STDCALL void WRAP_EXPORT(IoDetachDevice)
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
	IOTRACE("tail:%p", tail);
	
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	topdev->attached = tail->attached;
	IOTRACE("tail->attached:%p", tail->attached);
	ObDereferenceObject(topdev);

	for (tail = topdev->attached; tail; tail = tail->attached)
		tail->stack_size--;

	kspin_unlock_irql(&ntoskernel_lock, irql);
	IOEXIT(return);
}

STDCALL union power_state WRAP_EXPORT(PoSetPowerState)
	(struct device_object *dev_obj, enum power_state_type type,
	 union power_state state)
{
	union power_state ps;

	ps.device_state = PowerDeviceD0;
	return ps;
}

STDCALL NTSTATUS WRAP_EXPORT(PoCallDriver)
	(struct device_object *dev_obj, struct irp *irp)
{
	return IoCallDriver(dev_obj, irp);
}

STDCALL NTSTATUS WRAP_EXPORT(PoRequestPowerIrp)
	(struct device_object *dev_obj, UCHAR minor_fn,
	 union power_state power_state, void *completion_func,
	 void *context, struct irp *irp)
{
	UNIMPL();
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(IoRegisterDeviceInterface)
	(struct device_object *pdo, struct guid *guid_class,
	 struct unicode_string *reference, struct unicode_string *link)
{
	struct ansi_string ansi;

	/* check if pdo is valid */
	ansi.buf = "ndis";
	ansi.buflen = ansi.len = strlen(ansi.buf);
	TRACEENTER1("pdo: %p, ref: %p, link: %p", pdo, reference, link);
	return RtlAnsiStringToUnicodeString(reference, &ansi, TRUE);
}

STDCALL NTSTATUS WRAP_EXPORT(IoSetDeviceInterfaceState)
	(struct unicode_string *link, BOOLEAN enable)
{
	TRACEENTER1("link: %p, enable: %d", link, enable);
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(IoOpenDeviceRegistryKey)
	(struct device_object *pdo, ULONG type, ACCESS_MASK mask,
	 void **handle)
{
	struct wrapper_dev *wd;

	TRACEENTER1("pdo: %p", pdo);
	wd = pdo->reserved;
	*handle = wd->nmb;
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS WRAP_EXPORT(ZwQueryValueKey)
	(void *handle, struct unicode_string *name,
	 enum key_value_information_class class, void *info,
	 ULONG length, ULONG *res_length)
{
	NDIS_STATUS status;
	struct ndis_config_param *param;

	NdisReadConfiguration(&status, &param, handle, name,
			      NDIS_CONFIG_PARAM_STRING);
	if (status == NDIS_STATUS_SUCCESS) {
		*res_length = param->data.ustring.buflen;
		if (length < param->data.ustring.buflen) {
			RtlCopyMemory(info, param->data.ustring.buf,
				      *res_length);
			return STATUS_SUCCESS;
		} else
			return STATUS_BUFFER_TOO_SMALL;
	} else
		return STATUS_INVALID_PARAMETER;
}

STDCALL unsigned int WRAP_EXPORT(IoWMIRegistrationControl)
	(struct device_object *dev_obj, ULONG action)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;
	const int buf_len = 512;

	TRACEENTER2("%p, %d", dev_obj, action);

	switch (action) {
	case WMIREG_ACTION_REGISTER:
		irp = IoAllocateIrp(dev_obj->stack_size, FALSE);
		if (!irp) {
			ERROR("couldn't allocate irp");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		irp_sl = IoGetNextIrpStackLocation(irp);
		irp_sl->params.wmi.provider_id = (ULONG_PTR)dev_obj;
		irp_sl->params.wmi.data_path = (void *)WMIREGISTER;
		irp_sl->params.wmi.buf = kmalloc(buf_len, GFP_KERNEL);
		if (!irp_sl->params.wmi.buf) {
			IoFreeIrp(irp);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		irp_sl->params.wmi.buf_len = buf_len;
		IoCallDriver(dev_obj, irp);
		break;
	case WMIREG_ACTION_DEREGISTER:
		INFO("");
		break;
	case WMIREG_ACTION_REREGISTER:
		INFO("");
		break;
	case WMIREG_ACTION_UPDATE_GUIDS:
		ERROR("not implemented");
		break;
	default:
		ERROR("not implemented");
		break;
	}
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(IoCreateSymbolicLink)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(IoCreateUnprotectedSymbolicLink)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(IoDeleteSymbolicLink)(void){UNIMPL();}

#include "ntoskernel_io_exports.h"
