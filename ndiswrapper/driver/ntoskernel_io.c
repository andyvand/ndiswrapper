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
extern KSPIN_LOCK urb_list_lock;
extern struct nt_list object_list;

extern struct work_struct io_work;
extern struct nt_list io_workitem_list;
extern KSPIN_LOCK io_workitem_list_lock;

STDCALL NTSTATUS WRAP_EXPORT(IoGetDeviceProperty)
	(struct device_object *pdo,
	 enum device_registry_property dev_property,
	 ULONG buffer_len, void *buffer, ULONG *result_len)
{
	struct ansi_string ansi;
	struct unicode_string unicode;
	struct wrapper_dev *wd;
	char buf[32];

	wd = (struct wrapper_dev *)pdo->dev_ext;

	TRACEENTER1("dev_obj = %p, dev_property = %d, buffer_len = %u, "
		"buffer = %p, result_len = %p", pdo, dev_property,
		buffer_len, buffer, result_len);

	switch (dev_property) {
	case DevicePropertyDeviceDescription:
		if (buffer_len > 0 && buffer) {
			*result_len = sizeof(int);
			memset(buffer, 0xFF, *result_len);
			TRACEEXIT1(return STATUS_SUCCESS);
		} else {
			*result_len = sizeof(int);
			TRACEEXIT1(return STATUS_SUCCESS);
		}
		break;

	case DevicePropertyFriendlyName:
		if (buffer_len > 0 && buffer) {
			ansi.len = snprintf(buf, sizeof(buf), "%d",
					    wd->dev.usb->devnum);
			ansi.buf = buf;
			ansi.len = strlen(ansi.buf);
			if (ansi.len <= 0) {
				*result_len = 0;
				TRACEEXIT1(return STATUS_BUFFER_TOO_SMALL);
			}
			ansi.buflen = ansi.len;
			unicode.buf = buffer;
			unicode.buflen = buffer_len;
			DBGTRACE1("unicode.buflen = %d, ansi.len = %d",
					unicode.buflen, ansi.len);
			if (RtlAnsiStringToUnicodeString(&unicode, &ansi, 0)) {
				*result_len = 0;
				TRACEEXIT1(return STATUS_BUFFER_TOO_SMALL);
			} else {
				*result_len = unicode.len;
				TRACEEXIT1(return STATUS_SUCCESS);
			}
		} else {
			ansi.len = snprintf(buf, sizeof(buf), "%d",
					    wd->dev.usb->devnum);
			*result_len = 2 * (ansi.len + 1);
			TRACEEXIT1(return STATUS_BUFFER_TOO_SMALL);
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
				TRACEEXIT1(return STATUS_BUFFER_TOO_SMALL);
			} else {
				*result_len = unicode.len;
				TRACEEXIT1(return STATUS_SUCCESS);
			}
		} else {
				*result_len = 2 * (strlen(buf) + 1);
				TRACEEXIT1(return STATUS_SUCCESS);
		}
		break;
	default:
		TRACEEXIT1(return STATUS_INVALID_PARAMETER_2);
	}
}

STDCALL int WRAP_EXPORT(IoIsWdmVersionAvailable)
	(UCHAR major, UCHAR minor)
{
	TRACEENTER3("%d, %x", major, minor);
	if (major == 1 &&
	    (minor == 0x30 || // Windows 2003
	     minor == 0x20 || // Windows XP
	     minor == 0x10)) // Windows 2000
		TRACEEXIT3(return 1);
	TRACEEXIT3(return 0);
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
	DBGTRACE4("irp = %p, stack_size = %d", irp, stack_size);

	memset(irp, 0, size);
	irp->size = size;
	irp->stack_count = stack_size;
	irp->current_location = stack_size;
	IoGetCurrentIrpStackLocation(irp) = IRP_SL(irp, stack_size);

	USBTRACEEXIT(return);
}

STDCALL struct irp *WRAP_EXPORT(IoAllocateIrp)
	(char stack_size, BOOLEAN charge_quota)
{
	struct irp *irp;
	int irp_size;

	USBTRACE("stack_size = %d, charge_quota = %d",
		 stack_size, charge_quota);

	irp_size = IoSizeOfIrp(stack_size + 1);
	irp = kmalloc(irp_size, GFP_ATOMIC);
	if (irp) {
		USBTRACE("allocated irp %p", irp);
		IoInitializeIrp(irp, irp_size, stack_size + 1);
	}
#if 0
	DBG_BLOCK() {
		int i;
		for (i = 0; i < stack_size; i++)
			INFO("stack %d at %p", i, IRP_SL(irp, i));
	}
#endif

	USBTRACEEXIT(return irp);
}

STDCALL void WRAP_EXPORT(IoReuseIrp)
	(struct irp *irp, NTSTATUS status)
{
	USBTRACEENTER("irp = %p, status = %d", irp, status);
	if (irp)
		irp->io_status.status = status;
	USBTRACEEXIT(return);
}

STDCALL BOOLEAN WRAP_EXPORT(IoCancelIrp)
	(struct irp *irp)
{
	void (*cancel_routine)(struct device_object *, struct irp *) STDCALL;

	/* NB: this function may be called at DISPATCH_LEVEL */
	USBTRACEENTER("irp = %p", irp);

	if (!irp)
		return FALSE;
	DUMP_IRP(irp);
	irp->cancel_irql = kspin_lock_irql(&urb_list_lock, DISPATCH_LEVEL);
	cancel_routine = irp->cancel_routine;
	irp->cancel_routine = NULL;
	if (cancel_routine) {
		struct io_stack_location *irp_sl;

		irp_sl = IoGetCurrentIrpStackLocation(irp);
		/* cancel_routine will release the spin lock */
		cancel_routine(irp_sl->dev_obj, irp);
		USBTRACEEXIT(return TRUE);
	} else {
		irp->cancel = TRUE;
		kspin_unlock_irql(&urb_list_lock, irp->cancel_irql);
		USBTRACEEXIT(return FALSE);
	}
}

STDCALL void WRAP_EXPORT(IoFreeIrp)
	(struct irp *irp)
{
	USBTRACEENTER("irp = %p", irp);

	kfree(irp);

	USBTRACEEXIT(return);
}

STDCALL struct irp *WRAP_EXPORT(IoBuildAsynchronousFsdRequest)
	(ULONG major_fn, struct device_object *dev_obj, void *buffer,
	 ULONG length, LARGE_INTEGER *offset,
	 struct io_status_block *status)
{
	struct irp *irp;
	struct io_stack_location *irp_sl;

	irp = IoAllocateIrp(dev_obj->stack_size, FALSE);
	if (irp == NULL)
		return NULL;

	irp_sl = IoGetNextIrpStackLocation(irp);
	irp_sl->major_fn = major_fn;
	USBTRACE("major_fn: %d", major_fn);
	irp_sl->minor_fn = 0;
	irp_sl->flags = 0;
	irp_sl->control = 0;
	irp_sl->dev_obj = dev_obj;
	irp_sl->file_obj = NULL;
	irp_sl->completion_routine = NULL;

	if (dev_obj->flags & DO_DIRECT_IO) {
		DBGTRACE3("irp %p with DO_DIRECT_IO", irp);
		irp->mdl = IoAllocateMdl(buffer, length, FALSE, FALSE, irp);
		if (irp->mdl == NULL) {
			IoFreeIrp(irp);
			return NULL;
		}
	} else if (dev_obj->flags & DO_BUFFERED_IO) {
		DBGTRACE3("irp %p with DO_BUFFERED_IO", irp);
		irp->associated_irp.system_buffer =
			ExAllocatePoolWithTag(NonPagedPool, length, 0);
		if (irp->associated_irp.system_buffer == NULL) {
			IoFreeIrp(irp);
			return NULL;
		}
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
	USBTRACE("irp: %p", irp);
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

	USBTRACEENTER("");

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

	USBTRACE("irp: %p", irp);
	USBTRACEEXIT(return irp);
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
	USBTRACE("drv_obj: %p", drv_obj);
	IoSetNextIrpStackLocation(irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);

	irp_sl->dev_obj = dev_obj;
	major_func = drv_obj->major_func[irp_sl->major_fn];
	USBTRACE("major_func: %p", major_func);
	if (major_func)
		res = (*major_func)(dev_obj, irp);
	else {
		ERROR("major_function %d is not implemented",
		      irp_sl->major_fn);
		res = STATUS_NOT_SUPPORTED;
	}
	USBTRACEEXIT(return res);
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
	if (irp_sl->control & SL_PENDING_RETURNED)
		irp->pending_returned = TRUE;

	IoSkipCurrentIrpStackLocation(irp);

	while (irp->current_location <= irp->stack_count) {
		struct device_object *dev_obj;

		if (irp_sl->control & SL_PENDING_RETURNED)
			irp->pending_returned = TRUE;

		if (irp->current_location < irp->stack_count)
			dev_obj = IoGetCurrentIrpStackLocation(irp)->dev_obj;
		else
			dev_obj = NULL;

		if ((irp->io_status.status == STATUS_SUCCESS &&
		     irp_sl->control & CALL_ON_SUCCESS) ||
		    (irp->io_status.status != STATUS_SUCCESS &&
		     irp_sl->control & CALL_ON_ERROR) ||
		    (irp->cancel && (irp_sl->control & CALL_ON_CANCEL))) {
			if (irp_sl->completion_routine) {
				USBTRACE("calling completion_routine at: %p",
					 irp_sl->completion_routine);
				res = LIN2WIN3(irp_sl->completion_routine,
					       dev_obj, irp, irp_sl->context);
				if (res == STATUS_MORE_PROCESSING_REQUIRED)
					USBTRACEEXIT(return);
				USBTRACE("completion routine returned");
			} else {
				ERROR("completion routine not set for %p",
				      irp_sl);
			}
		} else {
			if (irp->current_location < irp->stack_count &&
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
		USBTRACE("setting event %p", irp->user_event);
		KeSetEvent(irp->user_event, prio_boost, FALSE);
	}

	USBTRACE("freeing irp %p", irp);
	while ((mdl = irp->mdl)) {
		irp->mdl = mdl->next;
		IoFreeMdl(mdl);
	}
	if (irp->flags & IRP_DEALLOCATE_BUFFER)
		ExFreePool(irp->associated_irp.system_buffer);

	IoFreeIrp(irp);
	USBTRACEEXIT(return);
}

STDCALL NTSTATUS
pdoDispatchInternalDeviceControl(struct device_object *pdo,
				 struct  irp *irp)
{
	struct io_stack_location *irp_sl;
	NTSTATUS ret;
	struct wrapper_dev *wd;

	DUMP_IRP(irp);

	if (irp->current_location < 0 ||
	    irp->current_location >= irp->stack_count) {
		ERROR("invalid irp: %p, %d, %d", irp, irp->current_location,
		      irp->stack_count);
		USBTRACEEXIT(return STATUS_FAILURE);
	}
	irp_sl = IoGetCurrentIrpStackLocation(irp);

	wd = pdo->dev_ext;
	if (wd->intf == NULL) {
		union nt_urb *nt_urb = URB_FROM_IRP(irp);
		NT_URB_STATUS(nt_urb) = USBD_STATUS_DEVICE_GONE;
		irp->io_status.status = STATUS_FAILURE;
		irp->io_status.status_info = 0;
		return STATUS_FAILURE;
	}
	switch (irp_sl->params.ioctl.code) {
#ifdef CONFIG_USB
	case IOCTL_INTERNAL_USB_SUBMIT_URB:
		ret = usb_submit_nt_urb(wd->dev.usb, irp);
		break;

	case IOCTL_INTERNAL_USB_RESET_PORT:
		ret = usb_reset_port(wd->dev.usb);
		break;
#endif
	default:
		ERROR("ioctl %08X NOT IMPLEMENTED!",
		      irp_sl->params.ioctl.code);
		ret = USBD_STATUS_INVALID_PARAMETER;
	}

	if (ret == STATUS_PENDING)
		irp_sl->control |= STATUS_PENDING;
	USBTRACEEXIT(return ret);
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
	DBGTRACE4("dev_obj: %p, irp: %p, context: %p",
		  dev_obj, irp, context);
	return STATUS_SUCCESS;
}

STDCALL NTSTATUS IopPassIrpDownAndWait(struct device_object *dev_obj,
				       struct irp *irp)
{
	struct wrapper_dev *wd;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	DBGTRACE4("dev_obj: %p, irp: %p", dev_obj, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	IoSetCompletionRoutine(irp, IopIrpWaitComplete, (void *)0x34b9f1,
			       TRUE, TRUE, TRUE);
	wd = dev_obj->dev_ext;
	status = IoCallDriver(wd->nmb->pdo, irp);
	return status;
}

STDCALL NTSTATUS IopPassIrpDown(struct device_object *dev_obj,
				struct irp *irp)
{
	struct wrapper_dev *wd;
	NTSTATUS status;

	DBGTRACE4("dev_obj: %p, irp: %p", dev_obj, irp);
	IoSkipCurrentIrpStackLocation(irp);
	wd = dev_obj->dev_ext;
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
	wd = pdo->dev_ext;
	DBGTRACE2("fn %d:%d, wd: %p", irp_sl->major_fn, irp_sl->minor_fn, wd);
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
		IoDeleteDevice(wd->nmb->fdo);
		IoDeleteDevice(wd->nmb->pdo);
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
	wd = pdo->dev_ext;
	DBGTRACE2("pdo: %p, fn: %d:%d, wd: %p",
		  pdo, irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_SET_POWER:
		state = irp_sl->params.power.state.device_state;
		pdev = wd->dev.pci;
		if (state == PowerDeviceD0) {
			DBGTRACE2("resuming device %p", wd);
			irp->io_status.status = STATUS_SUCCESS;
		} else {
			DBGTRACE2("suspending device %p", wd);
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

	DBGTRACE2("fdo: %p, irp: %p", fdo, irp);
	irp_sl = IoGetCurrentIrpStackLocation(irp);
	DBGTRACE2("irp_sl: %p, handler: %p",
		  irp_sl, irp_sl->completion_routine);
	wd = fdo->dev_ext;
	switch (irp_sl->minor_fn) {
	case IRP_MN_REMOVE_DEVICE:
		/*
		IoSkipCurrentIrpStackLocation(irp);
		IoCallDriver(wd->nmb->pdo, irp);
		IoDetachDevice(wd->nmb->pdo);
		IoDeleteDevice(fdo);
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
	TRACEENTER1("");

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
		TRACEEXIT1(return STATUS_INSUFFICIENT_RESOURCES);
	}
	TRACEEXIT1(return STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(PoStartNextPowerIrp)
	(struct irp *irp)
{
	TRACEENTER5("irp = %p", irp);
	TRACEEXIT5(return);
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
	TRACEEXIT3(return);
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
		if (cur)
			io_workitem_entry =
				container_of(cur, struct io_workitem_entry,
					     list);
		else
			io_workitem_entry = NULL;
		kspin_unlock_irql(&io_workitem_list_lock, irql);
		if (io_workitem_entry == NULL)
			break;
		kspin_unlock_irql(&io_workitem_list_lock, irql);
		io_workitem = io_workitem_entry->io_workitem;
		io_workitem->worker_routine(io_workitem->dev_obj,
					    io_workitem->context);
		ExFreePool(io_workitem_entry);
	}
	return;
}

STDCALL struct io_workitem *WRAP_EXPORT(IoAllocateWorkItem)
	(struct device_object *dev_obj)
{
	struct io_workitem *io_workitem;

	TRACEENTER3("%p", dev_obj);
	io_workitem = kmalloc(sizeof(*io_workitem), GFP_ATOMIC);
	if (!io_workitem)
		TRACEEXIT3(return NULL);

	io_workitem->dev_obj = dev_obj;
	TRACEEXIT3(return io_workitem);
}

STDCALL void WRAP_EXPORT(IoFreeWorkItem)
	(struct io_workitem *io_workitem)
{
	kfree(io_workitem);
	TRACEEXIT3(return);
}

STDCALL void WRAP_EXPORT(ExQueueWorkItem)
	(struct io_workitem *io_workitem, enum work_queue_type queue_type)
{
	struct io_workitem_entry *io_workitem_entry;
	KIRQL irql;

	TRACEENTER3("%s", "");
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
	TRACEEXIT3(return);
}

STDCALL NTSTATUS WRAP_EXPORT(IoAllocateDriverObjectExtension)
	(struct driver_object *drv_obj, void *client_id, ULONG extlen,
	 void **ext)
{
	struct custom_ext *ce;
	KIRQL irql;

	TRACEENTER2("%p, %p", drv_obj, client_id);
	ce = kmalloc(sizeof(*ce) + extlen, GFP_ATOMIC);
	if (ce == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	TRACEENTER1("custom_ext: %p", ce);
	ce->client_id = client_id;
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	InsertTailList(&drv_obj->drv_ext->custom_ext, &ce->list);
	kspin_unlock_irql(&ntoskernel_lock, irql);

	*ext = (void *)ce + sizeof(*ce);
	TRACEENTER1("ext: %p", *ext);
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL void *WRAP_EXPORT(IoGetDriverObjectExtension)
	(struct driver_object *drv_obj, void *client_id)
{
	struct nt_list *head, *ent;
	void *ret;
	KIRQL irql;

	TRACEENTER2("drv_obj: %p, client_id: %p", drv_obj, client_id);
	head = &drv_obj->drv_ext->custom_ext;
	ret = NULL;
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	nt_list_for_each(ent, head) {
		struct custom_ext *ce;
		ce = container_of(ent, struct custom_ext, list);
		if (ce->client_id == client_id) {
			ret = (void *)ce + sizeof(*ce);
			break;
		}
	}
	kspin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE2("ret: %p", ret);
	TRACEEXIT2(return ret);
}

void free_custom_ext(struct driver_extension *drv_ext)
{
	struct nt_list *head, *ent;
	KIRQL irql;

	TRACEENTER2("%p", drv_ext);
	head = &drv_ext->custom_ext;
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	while ((ent = RemoveHeadList(head)))
		kfree(ent);
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT2(return);
}

STDCALL NTSTATUS WRAP_EXPORT(IoCreateDevice)
	(struct driver_object *drv_obj, ULONG dev_ext_length,
	 struct unicode_string *dev_name, DEVICE_TYPE dev_type,
	 ULONG dev_chars, BOOLEAN exclusive, struct device_object **newdev)
{
	struct device_object *dev;

	TRACEENTER2("%p", drv_obj);
	dev = ALLOCATE_OBJECT(struct device_object, GFP_KERNEL,
			      OBJECT_TYPE_DEVICE);
	if (!dev)
		TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
	memset(dev, 0, sizeof(*dev));
	dev->type = dev_type;
	dev->drv_obj = drv_obj;
	dev->flags = 0;
	if (dev_ext_length) {
		dev->dev_ext = kmalloc(dev_ext_length, GFP_KERNEL);
		if (!dev->dev_ext) {
			ObDereferenceObject(dev);
			TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
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
	dev->dev_obj_ext = kmalloc(sizeof(*(dev->dev_obj_ext)), GFP_KERNEL);
	if (!dev->dev_obj_ext) {
		if (dev->dev_ext)
			kfree(dev->dev_ext);
		ObDereferenceObject(dev);
		TRACEEXIT2(return STATUS_INSUFFICIENT_RESOURCES);
	}
	dev->dev_obj_ext->type = 0;
	dev->dev_obj_ext->size = sizeof(*dev->dev_obj_ext);
	dev->dev_obj_ext->dev_obj = dev;
	drv_obj->dev_obj = dev;
	if (drv_obj->dev_obj)
		dev->next = drv_obj->dev_obj;
	else
		dev->next = NULL;
	DBGTRACE2("%p", dev);
	*newdev = dev;
	TRACEEXIT2(return STATUS_SUCCESS);
}

STDCALL void WRAP_EXPORT(IoDeleteDevice)
	(struct device_object *dev)
{
	struct device_object *prev;

	TRACEENTER2("%p", dev);
	if (dev == NULL)
		TRACEEXIT2(return);
	if (dev->dev_obj_ext)
		kfree(dev->dev_obj_ext);
	prev = dev->drv_obj->dev_obj;
	if (prev == dev)
		dev->drv_obj->dev_obj = dev->next;
	else {
		while (prev->next != dev)
			prev = prev->next;
		prev->next = dev->next;
	}
	ObDereferenceObject(dev);
	TRACEEXIT2(return);
}

STDCALL struct device_object *WRAP_EXPORT(IoGetAttachedDevice)
	(struct device_object *dev)
{
	struct device_object *d;
	KIRQL irql;

	TRACEENTER2("%p", dev);
	if (!dev)
		TRACEEXIT2(return NULL);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	for (d = dev; d->attached; d = d->attached)
		;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT2(return d);
}

STDCALL struct device_object *WRAP_EXPORT(IoGetAttachedDeviceReference)
	(struct device_object *dev)
{
	struct device_object *d;

	DBGTRACE2("%p", dev);
	if (!dev)
		TRACEEXIT2(return NULL);
	d = IoGetAttachedDevice(dev);
	ObReferenceObject(d);
	TRACEEXIT2(return d);
}

STDCALL struct device_object *WRAP_EXPORT(IoAttachDeviceToDeviceStack)
	(struct device_object *src, struct device_object *tgt)
{
	struct device_object *dst;
	KIRQL irql;

	DBGTRACE2("%p, %p", src, tgt);
	dst = IoGetAttachedDeviceReference(tgt);
	DBGTRACE3("stack_size: %d -> %d", dst->stack_size, src->stack_size);
	DBGTRACE3("%p", dst);
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	if (dst)
		dst->attached = src;
	src->attached = NULL;
	src->stack_size = dst->stack_size + 1;
	kspin_unlock_irql(&ntoskernel_lock, irql);
	DBGTRACE2("stack_size: %d -> %d", dst->stack_size, src->stack_size);
	TRACEEXIT2(return dst);
}

STDCALL void WRAP_EXPORT(IoDetachDevice)
	(struct device_object *topdev)
{
	struct device_object *tail;
	KIRQL irql;

	TRACEENTER2("%p", topdev);
	if (!topdev)
		TRACEEXIT2(return);
	tail = topdev->attached;
	if (!tail)
		TRACEEXIT2(return);
	DBGTRACE2("tail:%p", tail);
	
	irql = kspin_lock_irql(&ntoskernel_lock, DISPATCH_LEVEL);
	topdev->attached = tail->attached;
	DBGTRACE2("tail->attached:%p", tail->attached);
	ObDereferenceObject(topdev);

	for (tail = topdev->attached; tail; tail = tail->attached)
		tail->stack_size--;

	kspin_unlock_irql(&ntoskernel_lock, irql);
	TRACEEXIT2(return);
}

STDCALL NTSTATUS WRAP_EXPORT(PoCallDriver)
	(struct device_object *dev_obj, struct irp *irp)
{
	return IoCallDriver(dev_obj, irp);
}

STDCALL void WRAP_EXPORT(IoReleaseCancelSpinLock)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(IoCreateSymbolicLink)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(IoCreateUnprotectedSymbolicLink)(void){UNIMPL();}
STDCALL void WRAP_EXPORT(IoDeleteSymbolicLink)(void){UNIMPL();}

#include "ntoskernel_io_exports.h"
