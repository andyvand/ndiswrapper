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

#ifndef _PNP_H_
#define _PNP_H_

#include "ntoskernel.h"
#include "ndis.h"
#include "wrapndis.h"

driver_dispatch_t IopInvalidDeviceRequest;
driver_dispatch_t IopPassIrpDown;

STDCALL NTSTATUS IrpStopCompletion(struct device_object *dev_obj,
				   struct irp *irp, void *context);

struct device_object *alloc_pdo(struct driver_object *drv_obj);
void free_pdo(struct device_object *drv_obj);
int start_pdo(struct device_object *pdo);

NTSTATUS pnp_set_power_state(struct device_object *pdo,
			     enum device_power_state state);
NTSTATUS pnp_start_device(struct device_object *pdo);
NTSTATUS pnp_stop_device(struct device_object *pdo);
NTSTATUS pnp_remove_device(struct device_object *pdo);

int wrap_pnp_start_pci_device(struct pci_dev *pdev,
			      const struct pci_device_id *ent);
void __devexit wrap_pnp_remove_pci_device(struct pci_dev *pdev);
int wrap_pnp_suspend_pci_device(struct pci_dev *pdev, pm_message_t state);
int wrap_pnp_resume_pci_device(struct pci_dev *pdev);
#ifdef CONFIG_USB
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
int wrap_pnp_start_usb_device(struct usb_interface *intf,
			      const struct usb_device_id *usb_id);
void wrap_pnp_remove_usb_device(struct usb_interface *intf);
int wrap_pnp_suspend_usb_device(struct usb_interface *intf,
				pm_message_t state);
int wrap_pnp_resume_usb_device(struct usb_interface *intf);
#else
void *wrap_pnp_start_usb_device(struct usb_device *udev, unsigned int ifnum,
				const struct usb_device_id *usb_id);
void wrap_pnp_remove_usb_device(struct usb_device *udev, void *ptr);
#endif
#endif

#endif
