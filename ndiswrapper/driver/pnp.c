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
extern struct ndis_device *ndis_devices;
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
	irp_sl->params.start_device.allocated_resources =
		wd->resource_list;
	irp_sl->params.start_device.allocated_resources_translated =
		wd->resource_list;
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
	TRACEEXIT1(return status);
}

/* load driver for given device, if not already loaded */
static struct ndis_driver *load_driver(struct ndis_device *device)
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

/*
 * Called by PCI-subsystem for each PCI-card found.
 *
 * This function should not be marked __devinit because ndiswrapper
 * adds PCI_id's dynamically.
 */
int wrap_pnp_start_ndis_pci_device(struct pci_dev *pdev,
				   const struct pci_device_id *ent)
{
	int i, len, size, res = 0;
	struct ndis_device *device;
	struct ndis_driver *driver;
	struct wrapper_dev *wd;
	struct net_device *dev;
	struct device_object *pdo;
	struct driver_object *drv_obj;
	struct cm_partial_resource_descriptor *entry;
	struct cm_partial_resource_list *resource_list;

	TRACEENTER1("ent: %p", ent);

	DBGTRACE1("called for %04x:%04x:%04x:%04x", pdev->vendor, pdev->device,
		  pdev->subsystem_vendor, pdev->subsystem_device);

	device = &ndis_devices[ent->driver_data];
	driver = load_driver(device);
	if (!driver)
		return -ENODEV;
	DBGTRACE1("");
	/* first create pdo */
	drv_obj = find_bus_driver("PCI");
	if (!drv_obj)
		goto err_bus_driver;
	pdo = alloc_pdo(drv_obj);
	if (!pdo) {
		res = -ENODEV;
		goto err_bus_driver;
	}

	dev = init_netdev(&wd, device, driver);
	if (!dev) {
		ERROR("couldn't initialize network device");
		return -ENOMEM;
	}
	wd->dev.dev_type = NDIS_PCI_BUS;
	wd->dev.pci = pdev;
	DBGTRACE1("");
	pdo->reserved = wd;
	wd->nmb->pdo = pdo;
	DBGTRACE1("driver: %p", pdo->drv_obj);

	pci_set_drvdata(pdev, wd);
	res = pci_enable_device(pdev);
	if (res) {
		ERROR("couldn't enable PCI device: %08x", res);
		goto err_netdev;
	}

	res = pci_request_regions(pdev, DRIVER_NAME);
	if (res) {
		ERROR("couldn't request PCI regions: %08x", res);
		goto err_enable;
	}

	res = pci_set_power_state(pdev, PCI_D0);

#ifdef CONFIG_X86_64
	/* 64-bit broadcom driver doesn't work if DMA is allocated
	 * from over 1GB */
	if (strcmp(device->driver_name, "netbc564") == 0) {
		if (pci_set_dma_mask(pdev, 0x3fffffff) ||
		    pci_set_consistent_dma_mask(pdev, 0x3fffffff))
			WARNING("DMA mask couldn't be set; this driver "
				"may not work with more than 1GB RAM");
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_NETDEV_DEV(dev, &pdev->dev);
#endif

	size = sizeof(struct cm_resource_list) +
		sizeof(struct cm_partial_resource_descriptor) * MAX_RESOURCES;
	wd->resource_list = vmalloc(size);
	if (!wd->resource_list) {
		WARNING("couldn't allocate memory");
		goto err_regions;
	}
	resource_list = &wd->resource_list->list->partial_resource_list;
	resource_list->version = 1;
	i = len = 0;
	while (pci_resource_start(pdev, i)) {
		entry = &resource_list->partial_descriptors[len++];
		if (pci_resource_flags(pdev, i) & IORESOURCE_MEM) {
			entry->type = 3;
			entry->flags = 0;

		} else if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
			entry->type = 1;
			entry->flags = 1;
		}

		entry->share = 0;
		entry->u.generic.start =
			(ULONG_PTR)pci_resource_start(pdev, i);
		entry->u.generic.length = pci_resource_len(pdev, i);

		i++;
	}

	/* Put IRQ resource */
	entry = &resource_list->partial_descriptors[len++];
	entry->type = 2;
	entry->share = 0;
	entry->flags = 0;
	entry->u.interrupt.level = pdev->irq;
	entry->u.interrupt.vector = pdev->irq;
	entry->u.interrupt.affinity = -1;

	resource_list->length = len;
	size = (char *) (&resource_list->partial_descriptors[len]) -
		(char *)resource_list;

	DBGTRACE2("resource list v%d.%d len %d, size=%d",
		  resource_list->version, resource_list->revision,
		  resource_list->length, size);

	for (i = 0; i < len; i++) {
		DBGTRACE2("resource: %d: %Lx %d, %d",
			  resource_list->partial_descriptors[i].type,
			  resource_list->partial_descriptors[i].u.generic.start,
			  resource_list->partial_descriptors[i].u.generic.length,
			  resource_list->partial_descriptors[i].flags);
	}
	res = driver->drv_obj->drv_ext->add_device_func(driver->drv_obj,
							pdo);
	if (res != STATUS_SUCCESS)
		goto err_regions;
	DBGTRACE1("fdo: %p", wd->nmb->fdo);
	TRACEEXIT1(return 0);

err_regions:
	pci_release_regions(pdev);
err_enable:
	pci_disable_device(pdev);
err_netdev:
	free_netdev(dev);
err_bus_driver:
	pci_set_drvdata(pdev, NULL);
	TRACEEXIT1(return res);
}

/*
 * Remove one PCI-card.
 */
void __devexit wrap_pnp_remove_ndis_pci_device(struct pci_dev *pdev)
{
	struct wrapper_dev *wd;

	TRACEENTER1("%p", pdev);

	wd = (struct wrapper_dev *)pci_get_drvdata(pdev);

	TRACEENTER1("%p", wd);

	if (!wd)
		TRACEEXIT1(return);
	pnp_remove_device(wd);
}

#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int wrap_pnp_start_ndis_usb_device(struct usb_interface *intf,
				   const struct usb_device_id *usb_id)
#else
void *wrap_pnp_start_ndis_usb_device(struct usb_device *udev,
				     unsigned int ifnum,
				     const struct usb_device_id *usb_id)
#endif
{
	int res = 0;
	struct ndis_device *device;
	struct ndis_driver *driver;
	struct wrapper_dev *wd;
	struct net_device *dev;
	struct device_object *pdo;
	struct driver_object *drv_obj;

	TRACEENTER1("vendor: %04x, product: %04x, id: %p",
		    usb_id->idVendor, usb_id->idProduct, usb_id);

	device = &ndis_devices[usb_id->driver_info];
	/* RNDIS devices have two interfaces, so prevent from
	 * initializing the device again, if it has already been
	 * initialized */
	if (device->wd) {
		DBGTRACE1("device is already loaded");
		TRACEEXIT1(return 0);
	}

	driver = load_driver(device);
	if (!driver)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		return -ENODEV;
#else
		return NULL;
#endif
	dev = init_netdev(&wd, device, driver);
	if (!dev) {
		ERROR("couldn't initialize network device");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		return -ENOMEM;
#else
		return NULL;
#endif
	}

	/* first create pdo */
	drv_obj = find_bus_driver("USB");
	if (!drv_obj)
		goto err_net_dev;
	wd->dev.dev_type = NDIS_USB_BUS;
	DBGTRACE1("");
	pdo = alloc_pdo(drv_obj);
	if (!pdo) {
		res = -ENODEV;
		goto err_net_dev;
	}
	pdo->reserved = wd;
	wd->nmb->pdo = pdo;

	DBGTRACE1("");
	/* this creates (empty) fdo */
	res = driver->drv_obj->drv_ext->add_device_func(driver->drv_obj,
							pdo);
	if (res != STATUS_SUCCESS)
		goto err_pdo;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	SET_NETDEV_DEV(dev, &intf->dev);

	wd->dev.usb.udev = interface_to_usbdev(intf);
	usb_set_intfdata(intf, wd);
	wd->dev.usb.intf = intf;
#else
	wd->dev.usb.udev = udev;
	wd->dev.usb.intf = usb_ifnum_to_if(udev, ifnum);
#endif

	TRACEENTER1("calling ndis init routine");

	if (pnp_start_device(wd) != STATUS_SUCCESS) {
		ERROR("couldn't start device");
		res = -EINVAL;
		goto err_add_dev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return 0);
#else
	TRACEEXIT1(return wd);
#endif

err_add_dev:
	DeleteDevice(pdo);
err_pdo:
	IoDeleteDevice(pdo);
err_net_dev:
	free_netdev(dev);
	device->wd = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	TRACEEXIT1(return res);
#else
	TRACEEXIT1(return NULL);
#endif
}
#endif // CONFIG_USB

#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
void wrap_pnp_remove_ndis_usb_device(struct usb_interface *intf)
{
	struct wrapper_dev *wd;

	TRACEENTER1("");
	wd = (struct wrapper_dev *)usb_get_intfdata(intf);
	if (!wd)
		TRACEEXIT1(return);

	wd->dev.usb.intf = NULL;
	usb_set_intfdata(intf, NULL);
	if (!test_bit(HW_RMMOD, &wd->hw_status))
		miniport_surprise_remove(wd);
	pnp_remove_device(wd);
}
#else
void wrap_pnp_remove_ndis_usb_device(struct usb_device *udev, void *ptr)
{
	struct wrapper_dev *wd = (struct wrapper_dev *)ptr;

	TRACEENTER1("");
	if (!wd || !wd->dev.usb.intf)
		TRACEEXIT1(return);
	wd->dev.usb.intf = NULL;
	if (!test_bit(HW_RMMOD, &wd->hw_status))
		miniport_surprise_remove(wd);
	pnp_remove_device(wd);
}
#endif
#endif /* CONFIG_USB */

