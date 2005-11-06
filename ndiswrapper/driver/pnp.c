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

#include "usb.h"
#include "pnp.h"

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
	{
		status = irp->io_status.status = STATUS_NOT_IMPLEMENTED;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
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
	NTSTATUS status;
	NDIS_STATUS ndis_status;
	struct usbd_bus_interface_usbdi *usb_intf;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;
	IOTRACE("fn %d:%d, wd: %p", irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		ndis_status = miniport_init(wd);
		if (ndis_status == NDIS_STATUS_SUCCESS)
			status = STATUS_SUCCESS;
		else
			status = STATUS_FAILURE;
		break;
	case IRP_MN_QUERY_STOP_DEVICE:
	case IRP_MN_STOP_DEVICE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_REMOVE_DEVICE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_REMOVE_DEVICE:
		miniport_halt(wd);
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_INTERFACE:
		if (wd->dev.dev_type != NDIS_USB_BUS) {
			status = STATUS_SUCCESS;
			break;
		}
		IOTRACE("type: %x, size: %d, version: %d",
			irp_sl->params.query_intf.type->data1,
			irp_sl->params.query_intf.size,
			irp_sl->params.query_intf.version);
		usb_intf = (struct usbd_bus_interface_usbdi *)
			irp_sl->params.query_intf.intf;
		usb_intf->Context = wd;
		usb_intf->InterfaceReference = USBD_InterfaceReference;
		usb_intf->InterfaceDereference = USBD_InterfaceDereference;
		usb_intf->GetUSBDIVersion = USBD_InterfaceGetUSBDIVersion;
		usb_intf->QueryBusTime = USBD_InterfaceQueryBusTime;
		usb_intf->SubmitIsoOutUrb = USBD_InterfaceSubmitIsoOutUrb;
		usb_intf->QueryBusInformation =
			USBD_InterfaceQueryBusInformation;
		if (irp_sl->params.query_intf.version >=
		    USB_BUSIF_USBDI_VERSION_1)
			usb_intf->IsDeviceHighSpeed =
				USBD_InterfaceIsDeviceHighSpeed;
		if (irp_sl->params.query_intf.version >=
		    USB_BUSIF_USBDI_VERSION_2)
			usb_intf->LogEntry = USBD_InterfaceLogEntry;
		status = STATUS_SUCCESS;
		break;
	default:
		WARNING("minor_fn: %d not implemented", irp_sl->minor_fn);
		status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	irp->io_status.status = status;
	IOTRACE("res: %08X", status);
//	irp->io_status.status_info = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
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

NTSTATUS pnp_start_device(struct wrapper_dev *wd)
{
	struct device_object *fdo;
	struct irp *irp;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	fdo = IoGetAttachedDevice(wd->nmb->pdo);
	DBGTRACE1("fdo: %p", fdo);
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_START_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("Windows driver couldn't initialize the device (%08X)",
			status);
	TRACEEXIT1(return status);
}

NTSTATUS pnp_remove_device(struct wrapper_dev *wd)
{
	struct device_object *fdo;
	struct irp *irp;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	fdo = IoGetAttachedDevice(wd->nmb->pdo);
	DBGTRACE1("fdo: %p", fdo);
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_QUERY_REMOVE_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("status: %08X", status);
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_REMOVE_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("status: %08X", status);
	TRACEEXIT1(return status);
}

