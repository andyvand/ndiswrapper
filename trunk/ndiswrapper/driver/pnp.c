/*
 *  Copyright (C) 2005 Giridhar Pemmasani 
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
#include "wrapndis.h"

extern KSPIN_LOCK loader_lock;
extern struct nt_list ndis_drivers;

STDCALL NTSTATUS pdoDispatchInternalDeviceControl(struct device_object *pdo,
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
	NTSTATUS status;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	WARNING("IRP %d:%d not implemented",
		irp_sl->major_fn, irp_sl->minor_fn);
	irp->io_status.status = STATUS_NOT_IMPLEMENTED;
	irp->io_status.status_info = 0;
	status = irp->io_status.status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

int start_pdo(struct device_object *pdo)
{
	int ret, i, count;
	struct wrapper_dev *wd;
	struct pci_dev *pdev;
	struct cm_partial_resource_descriptor *entry;
	struct cm_partial_resource_list *partial_resource_list;

	wd = pdo->reserved;
	if (wd->dev.dev_type != NDIS_PCI_BUS)
		return 0;
	pdev = wd->dev.pci;
	pci_set_drvdata(pdev, wd);
	ret = pci_enable_device(pdev);
	if (ret) {
		ERROR("couldn't enable PCI device: %x", ret);
		return ret;
	}
	ret = pci_request_regions(pdev, DRIVER_NAME);
	if (ret) {
		ERROR("couldn't request PCI regions: %x", ret);
		goto err_enable;
	}
	pci_set_power_state(pdev, PCI_D0);
#ifdef CONFIG_X86_64
	/* 64-bit broadcom driver doesn't work if DMA is allocated
	 * from over 1GB */
	if (strcmp(wd->device->driver_name, "netbc564") == 0) {
		if (pci_set_dma_mask(pdev, 0x3fffffff) ||
		    pci_set_consistent_dma_mask(pdev, 0x3fffffff))
			WARNING("DMA mask couldn't be set; this driver "
				"may not work with more than 1GB RAM");
	}
#endif
	for (i = count = 0; pci_resource_start(pdev, i); i++)
		if ((pci_resource_flags(pdev, i) & IORESOURCE_MEM) ||
		    (pci_resource_flags(pdev, i) & IORESOURCE_IO))
			count++;
	DBGTRACE2("resources: %d", i);
	/* space for extra entry for IRQ is already available */
	wd->resource_list =
		kmalloc(sizeof(struct cm_resource_list) +
			sizeof(struct cm_partial_resource_descriptor) * count,
			GFP_KERNEL);
	if (!wd->resource_list) {
		WARNING("couldn't allocate memory");
		goto err_regions;
	}
	wd->resource_list->count = 1;
	wd->resource_list->list[0].interface_type = PCIBus;
	/* bus_number is not used by WDM drivers */
	wd->resource_list->list[0].bus_number = pdev->bus->number;

	partial_resource_list =
		&wd->resource_list->list->partial_resource_list;
	partial_resource_list->version = 1;
	partial_resource_list->revision = 1;
	partial_resource_list->count = count + 1;

	for (i = count = 0; pci_resource_start(pdev, i); i++) {
		entry = &partial_resource_list->partial_descriptors[count];
		DBGTRACE2("flags: %lx", pci_resource_flags(pdev, i));
		if (pci_resource_flags(pdev, i) & IORESOURCE_MEM) {
			entry->type = CmResourceTypeMemory;
			entry->flags = CM_RESOURCE_MEMORY_READ_WRITE;
			entry->share = CmResourceShareDeviceExclusive;
		} else if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
			entry->type = CmResourceTypePort;
			entry->flags = CM_RESOURCE_PORT_IO;
			entry->share = CmResourceShareDeviceExclusive;
		} else
			continue;
		/* TODO: Add other resource types? */
		entry->u.generic.start =
			(ULONG_PTR)pci_resource_start(pdev, i);
		entry->u.generic.length = pci_resource_len(pdev, i);
		count++;
	}

	/* put IRQ resource at the end */
	entry = &partial_resource_list->partial_descriptors[count++];
	entry->type = CmResourceTypeInterrupt;
	entry->flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
	/* we assume all devices use shared IRQ */
	entry->share = CmResourceShareShared;
	entry->u.interrupt.level = DISPATCH_LEVEL;
	entry->u.interrupt.vector = pdev->irq;
	entry->u.interrupt.affinity = -1;

	DBGTRACE2("resource list count %d, irq: %d",
		  partial_resource_list->count, pdev->irq);
	return 0;
err_regions:
	pci_release_regions(pdev);
err_enable:
	pci_disable_device(pdev);
	return -EINVAL;
}

STDCALL NTSTATUS pdoDispatchPnp(struct device_object *pdo, struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	NTSTATUS status;
	struct usbd_bus_interface_usbdi *usb_intf;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;
	IOTRACE("fn %d:%d, wd: %p", irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_START_DEVICE:
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_INTERFACE:
		if (wd->dev.dev_type != NDIS_USB_BUS) {
			status = STATUS_NOT_IMPLEMENTED;
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
	case IRP_MN_REMOVE_DEVICE:
		IoDeleteDevice(wd->nmb->pdo);
		if (wd->dev.dev_type == NDIS_PCI_BUS) {
			struct pci_dev *pdev = wd->dev.pci;
			pci_release_regions(pdev);
			pci_disable_device(pdev);
			pci_set_drvdata(pdev, NULL);
		}
		status = STATUS_SUCCESS;
		break;
	default:
		status = STATUS_SUCCESS;
		break;
	}
	irp->io_status.status = status;
	IOTRACE("res: %08X", status);
//	irp->io_status.status_info = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	IOEXIT(return status);
}

STDCALL NTSTATUS IopPassIrpDown(struct device_object *dev_obj,
				struct irp *irp)
{
	IoSkipCurrentIrpStackLocation(irp);
	return IoCallDriver(dev_obj, irp);
}

STDCALL NTSTATUS IrpStopCompletion(struct device_object *dev_obj,
				   struct irp *irp, void *context)
{
	IOENTER("dev_obj: %p, irp: %p, context: %p", dev_obj, irp, context);
	IOEXIT(return STATUS_MORE_PROCESSING_REQUIRED);
}

STDCALL NTSTATUS pdoDispatchPower(struct device_object *pdo,
				  struct irp *irp)
{
	struct io_stack_location *irp_sl;
	struct wrapper_dev *wd;
	enum device_power_state state;
	struct pci_dev *pdev;
	NTSTATUS status;

	irp_sl = IoGetCurrentIrpStackLocation(irp);
	wd = pdo->reserved;
	IOTRACE("pdo: %p, fn: %d:%d, wd: %p",
		  pdo, irp_sl->major_fn, irp_sl->minor_fn, wd);
	switch (irp_sl->minor_fn) {
	case IRP_MN_SET_POWER:
		state = irp_sl->params.power.state.device_state;
		if (state == PowerDeviceD0) {
			IOTRACE("resuming device %p", wd);
			if (wd->dev.dev_type == NDIS_PCI_BUS) {
				pdev = wd->dev.pci;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
				pci_restore_state(pdev);
#else
				pci_restore_state(pdev, wd->pci_state);
#endif
			}
		} else {
			IOTRACE("suspending device %p", wd);
			if (wd->dev.dev_type == NDIS_PCI_BUS) {
				pdev = wd->dev.pci;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
				pci_save_state(pdev);
#else
				pci_save_state(pdev, wd->pci_state);
#endif
			}
		}
		status = STATUS_SUCCESS;
		break;
	case IRP_MN_QUERY_POWER:
		status = STATUS_SUCCESS;
		break;
	default:
		status = STATUS_SUCCESS;
		ERROR("invalid power irp");
		break;
	}
	irp->io_status.status_info = 0;
	irp->io_status.status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS pnp_set_power_state(struct wrapper_dev *wd,
			     enum device_power_state state)
{
	struct device_object *fdo;
	struct irp *irp;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	fdo = IoGetAttachedDevice(wd->nmb->pdo);
	if (state > PowerDeviceD0) {
		irp = IoAllocateIrp(fdo->stack_size, FALSE);
		irp_sl = IoGetNextIrpStackLocation(irp);
		DBGTRACE2("irp = %p, stack = %p", irp, irp_sl);
		irp_sl->major_fn = IRP_MJ_POWER;
		irp_sl->minor_fn = IRP_MN_QUERY_POWER;
		irp_sl->params.power.state.device_state = state;
		irp->io_status.status = STATUS_NOT_SUPPORTED;
		status = IoCallDriver(fdo, irp);
		if (status != STATUS_SUCCESS)
			WARNING("query power returns %08X", status);
	}
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE2("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_POWER;
	irp_sl->minor_fn = IRP_MN_SET_POWER;
	irp_sl->params.power.state.device_state = state;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("set power returns %08X", status);
	TRACEEXIT1(return status);
}

NTSTATUS pnp_start_device(struct wrapper_dev *wd)
{
	struct device_object *fdo;
	struct irp *irp;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	fdo = IoGetAttachedDevice(wd->nmb->pdo);
	DBGTRACE1("fdo: %p, irql: %d", fdo, current_irql());
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	/* TODO: for now we use translated resources as raw resources */
	irp_sl->params.start_device.allocated_resources =
		wd->resource_list;
	irp_sl->params.start_device.allocated_resources_translated =
		wd->resource_list;
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_START_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status == STATUS_SUCCESS)
		fdo->drv_obj->drv_ext->count++;
	else
		WARNING("Windows driver couldn't initialize the device (%08X)",
			status);
	TRACEEXIT1(return status);
}

NTSTATUS pnp_stop_device(struct wrapper_dev *wd)
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
	irp_sl->minor_fn = IRP_MN_QUERY_STOP_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("status: %08X", status);
	/* for now we ignore query status */
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_STOP_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("status: %08X", status);
	TRACEEXIT2(return status);
}

NTSTATUS pnp_remove_device(struct wrapper_dev *wd)
{
	struct device_object *fdo;
	struct driver_object *drv_obj;
	struct irp *irp;
	struct io_stack_location *irp_sl;
	NTSTATUS status;

	fdo = IoGetAttachedDevice(wd->nmb->pdo);
	drv_obj = fdo->drv_obj;
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
	/* for now we ignore query status */
	irp = IoAllocateIrp(fdo->stack_size, FALSE);
	irp_sl = IoGetNextIrpStackLocation(irp);
	DBGTRACE1("irp = %p, stack = %p", irp, irp_sl);
	irp_sl->major_fn = IRP_MJ_PNP;
	irp_sl->minor_fn = IRP_MN_REMOVE_DEVICE;
	irp->io_status.status = STATUS_NOT_SUPPORTED;
	status = IoCallDriver(fdo, irp);
	if (status != STATUS_SUCCESS)
		WARNING("status: %08X", status);

	DBGTRACE1("drv_obj: %p", drv_obj);
	/* we don't unload the driver itself, for now */
	if (--drv_obj->drv_ext->count <= 0 &&
	    drv_obj && drv_obj->unload)
		LIN2WIN1(drv_obj->unload, drv_obj);
	TRACEEXIT1(return status);
}

/* load driver for given device, if not already loaded */
struct ndis_driver *load_driver(struct ndis_device *device)
{
	int err, found;
	struct ndis_driver *ndis_driver;
	KIRQL irql;

	TRACEENTER1("device: %04X:%04X:%04X:%04X", device->vendor,
		    device->device, device->subvendor, device->subdevice);
	found = 0;
	ndis_driver = NULL;
	irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
	nt_list_for_each_entry(ndis_driver, &ndis_drivers, list) {
		if (strcmp(ndis_driver->name, device->driver_name) == 0) {
			DBGTRACE1("driver %s already loaded",
				  ndis_driver->name);
			found = 1;
			break;
		}
	}
	kspin_unlock_irql(&loader_lock, irql);

	if (found)
		TRACEEXIT1(return ndis_driver);
	else {
		char *argv[] = {"loadndisdriver", 
#if defined DEBUG && DEBUG >= 1
				"1",
#else
				"0",
#endif
				UTILS_VERSION, device->driver_name,
				device->conf_file_name, NULL};
		char *env[] = {NULL};

		DBGTRACE1("loading driver %s", device->driver_name);
		err = call_usermodehelper("/sbin/loadndisdriver", argv, env
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
					  , 1
#endif
			);

		if (err) {
			ERROR("loadndiswrapper failed (%d); check system log "
			      "for messages from 'loadndisdriver'", err);
			TRACEEXIT1(return NULL);
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		/* wait for the driver to load and initialize */
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
#endif
		found = 0;
		irql = kspin_lock_irql(&loader_lock, DISPATCH_LEVEL);
		nt_list_for_each_entry(ndis_driver, &ndis_drivers, list) {
			if (strcmp(ndis_driver->name,
				   device->driver_name) == 0) {
				found = 1;
				break;
			}
		}
		kspin_unlock_irql(&loader_lock, irql);

		if (!found) {
			ERROR("couldn't load driver '%s'",
			      device->driver_name);
			TRACEEXIT1(return NULL);
		}

		DBGTRACE1("driver %s is loaded", ndis_driver->name);
	}
	TRACEEXIT1(return ndis_driver);
}
